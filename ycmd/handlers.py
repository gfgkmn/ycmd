# Copyright (C) 2013-2020 ycmd contributors
#
# This file is part of ycmd.
#
# ycmd is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ycmd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ycmd.  If not, see <http://www.gnu.org/licenses/>.

import json
import platform
import sys
import time
import traceback
import os
import tempfile
import subprocess


import ycmd.web_plumbing
from ycmd import extra_conf_store, hmac_plugin, server_state, user_options_store
from ycmd.responses import ( BuildExceptionResponse,
                             BuildCompletionResponse,
                             BuildResolveCompletionResponse,
                             BuildSignatureHelpResponse,
                             BuildSignatureHelpAvailableResponse,
                             BuildSemanticTokensResponse,
                             BuildInlayHintsResponse,
                             SignatureHelpAvailalability,
                             UnknownExtraConf )
from ycmd.request_wrap import RequestWrap
from ycmd.completers.completer_utils import FilterAndSortCandidatesWrap
from ycmd.utils import LOGGER, StartThread, ImportCore
ycm_core = ImportCore()


_server_state = None
_hmac_secret = bytes()
app = ycmd.web_plumbing.AppProducer()
wsgi_server = None


def _NormalizeFileData( request_json ):
  """
  Normalize file_data to ensure all files have 'contents' field.
  Handles different content formats: diff or reading from disk.
  Also handles file creation when requested.
  """
  if 'file_data' not in request_json:
    return request_json

  # Make a copy to avoid modifying the original
  normalized = dict( request_json )
  normalized['file_data'] = {}

  for filepath, file_data in request_json['file_data'].items():
    normalized_file_data = dict( file_data )

    # Check if we need to create or update this file on the server
    # This flag is set when:
    # 1. First time entering a notebook (create base file)
    # 2. After explicit save (update base file)
    create_if_needed = file_data.get('create_if_needed', False)

    # If contents already exists
    if 'contents' in file_data:
      contents = file_data['contents']

      # If create_if_needed is True, write/update the file to disk
      if create_if_needed:
        # Security check: only allow file creation in temp directories
        temp_dirs = [
          tempfile.gettempdir(),  # System temp dir (e.g., /tmp on Unix)
          '/tmp',
          '/var/tmp',
          os.path.join( tempfile.gettempdir(), 'ycmd' )
        ]

        # Check if filepath is in one of the allowed temp directories
        is_in_temp = any(
          os.path.abspath( filepath ).startswith( os.path.abspath( temp_dir ) )
          for temp_dir in temp_dirs if os.path.exists( temp_dir )
        )

        if not is_in_temp:
          LOGGER.warning(
            f'Refused to create/update file {filepath} - create_if_needed only allowed in temp directories'
          )
        else:
          try:
            # Create directory if it doesn't exist
            directory = os.path.dirname( filepath )
            if directory and not os.path.exists( directory ):
              os.makedirs( directory, exist_ok=True )

            # Write the file (create new or overwrite existing)
            with open( filepath, 'w', encoding='utf-8' ) as f:
              f.write( contents )

            if os.path.exists( filepath ):
              LOGGER.info( f'Updated temp file {filepath} as requested by client' )
            else:
              LOGGER.info( f'Created temp file {filepath} as requested by client' )
          except Exception as e:
            LOGGER.error( f'Failed to create/update temp file {filepath}: {e}' )

      normalized_file_data['contents'] = contents
      # Remove the create_if_needed flag from normalized data
      normalized_file_data.pop('create_if_needed', None)
      normalized['file_data'][filepath] = normalized_file_data
      continue

    # If diff exists, apply it to get contents
    if 'diff' in file_data:
      contents = _ApplyDiff( filepath, file_data['diff'] )

      # If create_if_needed is True, update the base file with the new content
      # This happens after explicit saves
      if create_if_needed:
        # Security check: only allow file updates in temp directories
        temp_dirs = [
          tempfile.gettempdir(),
          '/tmp',
          '/var/tmp',
          os.path.join( tempfile.gettempdir(), 'ycmd' )
        ]

        is_in_temp = any(
          os.path.abspath( filepath ).startswith( os.path.abspath( temp_dir ) )
          for temp_dir in temp_dirs if os.path.exists( temp_dir )
        )

        if is_in_temp and os.path.exists( filepath ):
          try:
            with open( filepath, 'w', encoding='utf-8' ) as f:
              f.write( contents )
            LOGGER.info( f'Updated base file {filepath} after save' )
          except Exception as e:
            LOGGER.warning( f'Failed to update base file {filepath}: {e}' )

      normalized_file_data['contents'] = contents
      # Remove diff from normalized data
      normalized_file_data.pop('diff', None)
      normalized_file_data.pop('create_if_needed', None)
      normalized['file_data'][filepath] = normalized_file_data
      continue

    # Otherwise, read from disk (for unmodified files)
    contents = _ReadFileContents( filepath )
    normalized_file_data['contents'] = contents
    normalized_file_data.pop('create_if_needed', None)
    normalized['file_data'][filepath] = normalized_file_data

  return normalized


def _ReadFileContents( filepath ):
  """Read file contents from disk."""
  if os.path.exists( filepath ):
    try:
      with open( filepath, 'r', encoding='utf-8' ) as f:
        return f.read()
    except Exception as e:
      LOGGER.warning( f'Failed to read file {filepath}: {e}' )
  return ''


def _ApplyDiff( filepath, diff_content ):
  """Apply a unified diff to the file on disk to get current content."""
  if not os.path.exists( filepath ):
    LOGGER.warning( f'Cannot apply diff: file {filepath} does not exist' )
    return ''

  try:
    # Read the original file
    with open( filepath, 'r', encoding='utf-8' ) as f:
      original_content = f.read()

    # Create temp files for patch operation
    with tempfile.NamedTemporaryFile( mode='w', suffix='.orig', delete=False ) as orig_file:
      orig_file.write( original_content )
      orig_path = orig_file.name

    with tempfile.NamedTemporaryFile( mode='w', suffix='.diff', delete=False ) as diff_file:
      diff_file.write( diff_content )
      diff_path = diff_file.name

    # Create output temp file
    with tempfile.NamedTemporaryFile( mode='w', suffix='.patched', delete=False ) as out_file:
      out_path = out_file.name

    try:
      # Apply the patch to a file instead of stdout to avoid status messages
      # Use --silent to suppress informational messages
      result = subprocess.run(
        ['patch', '--silent', '-o', out_path, orig_path],
        stdin=open( diff_path, 'r' ),
        capture_output=True,
        text=True
      )

      if result.returncode == 0:
        # Read the patched content from the output file
        with open( out_path, 'r', encoding='utf-8' ) as f:
          return f.read()
      else:
        LOGGER.warning( f'Failed to apply diff for {filepath}: {result.stderr}' )
        # Fall back to original content
        return original_content

    finally:
      # Clean up temp files
      if os.path.exists( orig_path ):
        os.unlink( orig_path )
      if os.path.exists( diff_path ):
        os.unlink( diff_path )
      if os.path.exists( out_path ):
        os.unlink( out_path )

  except Exception as e:
    LOGGER.error( f'Error applying diff for {filepath}: {e}' )
    # Try to return file content as fallback
    return _ReadFileContents( filepath )


@app.post( '/event_notification' )
def EventNotification( request, response ):
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )
  event_name = request_data[ 'event_name' ]
  LOGGER.debug( 'Event name: %s', event_name )

  event_handler = 'On' + event_name
  getattr( _server_state.GetGeneralCompleter(), event_handler )( request_data )

  filetypes = request_data[ 'filetypes' ]
  response_data = None
  if _server_state.FiletypeCompletionUsable( filetypes ):
    response_data = getattr( _server_state.GetFiletypeCompleter( filetypes ),
                             event_handler )( request_data )

  if response_data:
    return _JsonResponse( response_data, response )
  return _JsonResponse( {}, response )


@app.get( '/signature_help_available' )
def GetSignatureHelpAvailable( request, response ):
  if request.query.subserver:
    filetype = request.query.subserver
    try:
      completer = _server_state.GetFiletypeCompleter( [ filetype ] )
    except ValueError:
      return _JsonResponse( BuildSignatureHelpAvailableResponse(
        SignatureHelpAvailalability.NOT_AVAILABLE ), response )
    value = completer.SignatureHelpAvailable()
    return _JsonResponse( BuildSignatureHelpAvailableResponse( value ),
                          response )
  else:
    raise RuntimeError( 'Subserver not specified' )


@app.post( '/run_completer_command' )
def RunCompleterCommand( request, response ):
  # Preprocess the request to normalize file_data contents
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )
  # LOGGER.info( f"i receive a request: \n{json.dumps(request.json, indent=2)}" )
  completer = _GetCompleterForRequestData( request_data )

  # Get server info from request environment
  env = request.env
  scheme = env.get('wsgi.url_scheme', 'http')
  server_name = env.get('SERVER_NAME', 'localhost')
  server_port = env.get('SERVER_PORT', '80')

  # Build full URL
  full_url = f"{scheme}://{server_name}:{server_port}{request.path}"

  LOGGER.debug(f"[ycmd] Received POST /run_completer_command")
  LOGGER.debug(f"[ycmd] Server: {server_name}:{server_port}")
  LOGGER.debug(f"[ycmd] URL: {full_url}")
  LOGGER.debug(f"[ycmd] Request parameters: {request.json}")

  return _JsonResponse( completer.OnUserCommand(
      request_data[ 'command_arguments' ],
      request_data ), response )


@app.post( '/resolve_fixit' )
def ResolveFixit( request, response ):
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )
  completer = _GetCompleterForRequestData( request_data )

  return _JsonResponse( completer.ResolveFixit( request_data ), response )


@app.post( '/completions' )
def GetCompletions( request, response ):
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )
  do_filetype_completion = _server_state.ShouldUseFiletypeCompleter(
    request_data )
  LOGGER.debug( 'Using filetype completion: %s', do_filetype_completion )

  errors = None
  completions = None

  if do_filetype_completion:
    try:
      filetype_completer = _server_state.GetFiletypeCompleter(
        request_data[ 'filetypes' ] )
      completions = filetype_completer.ComputeCandidates( request_data )
    except Exception as exception:
      if request_data[ 'force_semantic' ]:
        # user explicitly asked for semantic completion, so just pass the error
        # back
        raise

      # store the error to be returned with results from the identifier
      # completer
      LOGGER.exception( 'Exception from semantic completer (using general)' )
      stack = traceback.format_exc()
      errors = [ BuildExceptionResponse( exception, stack ) ]

  if not completions and not request_data[ 'force_semantic' ]:
    completions = _server_state.GetGeneralCompleter().ComputeCandidates(
      request_data )

  return _JsonResponse(
      BuildCompletionResponse( completions if completions else [],
                               request_data[ 'start_column' ],
                               errors = errors ), response )


@app.post( '/resolve_completion' )
def ResolveCompletionItem( request, response ):
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )
  completer = _GetCompleterForRequestData( request_data )

  errors = None
  completion = None
  try:
    completion = completer.ResolveCompletionItem( request_data )
  except Exception as e:
    errors = [ BuildExceptionResponse( e, traceback.format_exc() ) ]

  return _JsonResponse( BuildResolveCompletionResponse( completion, errors ),
                        response )


@app.post( '/signature_help' )
def GetSignatureHelp( request, response ):
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )

  if not _server_state.FiletypeCompletionUsable( request_data[ 'filetypes' ],
                                                 silent = True ):
    return _JsonResponse( BuildSignatureHelpResponse( None ), response )

  errors = None
  signature_info = None

  try:
    filetype_completer = _server_state.GetFiletypeCompleter(
      request_data[ 'filetypes' ] )
    signature_info = filetype_completer.ComputeSignatures( request_data )
  except Exception as exception:
    LOGGER.exception( 'Exception from semantic completer during sig help' )
    errors = [ BuildExceptionResponse( exception, traceback.format_exc() ) ]

  # No fallback for signature help. The general completer is unlikely to be able
  # to offer anything of for that here.
  return _JsonResponse(
      BuildSignatureHelpResponse( signature_info, errors = errors ), response )


@app.post( '/semantic_tokens' )
def GetSemanticTokens( request, response ):
  LOGGER.info( 'Received semantic tokens request' )
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )

  if not _server_state.FiletypeCompletionUsable( request_data[ 'filetypes' ],
                                                 silent = True ):
    return _JsonResponse( BuildSemanticTokensResponse( None ), response )

  errors = None
  semantic_tokens = None

  try:
    filetype_completer = _server_state.GetFiletypeCompleter(
      request_data[ 'filetypes' ] )
    semantic_tokens = filetype_completer.ComputeSemanticTokens( request_data )
  except Exception as exception:
    LOGGER.exception(
      'Exception from semantic completer during tokens request' )
    errors = [ BuildExceptionResponse( exception, traceback.format_exc() ) ]

  # No fallback for signature help. The general completer is unlikely to be able
  # to offer anything of for that here.
  return _JsonResponse(
      BuildSemanticTokensResponse( semantic_tokens, errors = errors ),
      response )


@app.post( '/inlay_hints' )
def GetInlayHints( request, response ):
  LOGGER.info( 'Received inlay hints request' )
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )

  if not _server_state.FiletypeCompletionUsable( request_data[ 'filetypes' ],
                                                 silent = True ):
    return _JsonResponse( BuildInlayHintsResponse( None ), response )

  errors = None
  inlay_hints = None

  try:
    filetype_completer = _server_state.GetFiletypeCompleter(
      request_data[ 'filetypes' ] )
    inlay_hints = filetype_completer.ComputeInlayHints( request_data )
  except Exception as exception:
    LOGGER.exception(
      'Exception from semantic completer during tokens request' )
    errors = [ BuildExceptionResponse( exception, traceback.format_exc() ) ]

  # No fallback for signature help. The general completer is unlikely to be able
  # to offer anything of for that here.
  return _JsonResponse(
      BuildInlayHintsResponse( inlay_hints, errors = errors ), response )


@app.post( '/filter_and_sort_candidates' )
def FilterAndSortCandidates( request, response ):
  # Not using RequestWrap because no need and the requests coming in aren't like
  # the usual requests we handle.
  request_data = request.json

  return _JsonResponse( FilterAndSortCandidatesWrap(
    request_data[ 'candidates' ],
    request_data[ 'sort_property' ],
    request_data[ 'query' ],
    _server_state.user_options[ 'max_num_candidates' ] ), response )


@app.get( '/healthy' )
def GetHealthy( request, response ):
  if request.query.subserver:
    filetype = request.query.subserver
    completer = _server_state.GetFiletypeCompleter( [ filetype ] )
    return _JsonResponse( completer.ServerIsHealthy(), response )
  return _JsonResponse( True, response )


@app.get( '/ready' )
def GetReady( request, response ):
  if request.query.subserver:
    filetype = request.query.subserver
    completer = _server_state.GetFiletypeCompleter( [ filetype ] )
    return _JsonResponse( completer.ServerIsReady(), response )
  return _JsonResponse( True, response )


@app.post( '/semantic_completion_available' )
def FiletypeCompletionAvailable( request, response ):
  return _JsonResponse( _server_state.FiletypeCompletionAvailable(
      RequestWrap( request.json )[ 'filetypes' ] ), response )


@app.post( '/defined_subcommands' )
def DefinedSubcommands( request, response ):
  completer = _GetCompleterForRequestData( RequestWrap( request.json ) )

  return _JsonResponse( completer.DefinedSubcommands(), response )


@app.post( '/detailed_diagnostic' )
def GetDetailedDiagnostic( request, response ):
  # Normalize file_data to ensure all files have 'contents' field
  processed_json = _NormalizeFileData( request.json )
  request_data = RequestWrap( processed_json )
  completer = _GetCompleterForRequestData( request_data )

  return _JsonResponse( completer.GetDetailedDiagnostic( request_data ),
                        response )


@app.post( '/load_extra_conf_file' )
def LoadExtraConfFile( request, response ):
  request_data = RequestWrap( request.json, validate = False )
  extra_conf_store.Load( request_data[ 'filepath' ], force = True )

  return _JsonResponse( True, response )


@app.post( '/ignore_extra_conf_file' )
def IgnoreExtraConfFile( request, response ):
  request_data = RequestWrap( request.json, validate = False )
  extra_conf_store.Disable( request_data[ 'filepath' ] )

  return _JsonResponse( True, response )


@app.post( '/debug_info' )
def DebugInfo( request, response ):
  request_data = RequestWrap( request.json )

  has_clang_support = ycm_core.HasClangSupport()
  clang_version = ycm_core.ClangVersion() if has_clang_support else None

  filepath = request_data[ 'filepath' ]
  try:
    extra_conf_path = extra_conf_store.ModuleFileForSourceFile( filepath )
    is_loaded = bool( extra_conf_path )
  except UnknownExtraConf as error:
    extra_conf_path = error.extra_conf_file
    is_loaded = False

  result = {
    'python': {
      'executable': sys.executable,
      'version': platform.python_version()
    },
    'clang': {
      'has_support': has_clang_support,
      'version': clang_version
    },
    'extra_conf': {
      'path': extra_conf_path,
      'is_loaded': is_loaded
    },
    'completer': None
  }

  try:
    result[ 'completer' ] = _GetCompleterForRequestData(
        request_data ).DebugInfo( request_data )
  except Exception:
    LOGGER.exception( 'Error retrieving completer debug info' )

  return _JsonResponse( result, response )


@app.post( '/shutdown' )
def Shutdown( request, response ):
  ServerShutdown()
  return _JsonResponse( True, response )


@app.post( '/receive_messages' )
def ReceiveMessages( request, response ):
  # Receive messages is a "long-poll" handler.
  # The client makes the request with a long timeout (1 hour).
  # When we have data to send, we send it and close the socket.
  # The client then sends a new request.
  request_data = RequestWrap( request.json )
  try:
    completer = _GetCompleterForRequestData( request_data )
  except Exception:
    # No semantic completer for this filetype, don't requery. This is not an
    # error.
    return _JsonResponse( False, response )

  return _JsonResponse( completer.PollForMessages( request_data ), response )


def ErrorHandler( httperror : ycmd.web_plumbing.HTTPError,
                  response : ycmd.web_plumbing.Response ):
  body = _JsonResponse( BuildExceptionResponse( httperror.exception,
                                                httperror.traceback ),
                        response )
  hmac_plugin.SetHmacHeader( body, _hmac_secret, response )
  return body


# For every error Bottle encounters it will use this as the default handler
app.SetErrorHandler( ErrorHandler )


def _JsonResponse( data, response : ycmd.web_plumbing.Response ):
  response.set_header( 'Content-Type', 'application/json' )
  return json.dumps( data,
                     separators = ( ',', ':' ),
                     default = _UniversalSerialize )


def _UniversalSerialize( obj ):
  try:
    serialized = obj.__dict__.copy()
    serialized[ 'TYPE' ] = type( obj ).__name__
    return serialized
  except AttributeError:
    return str( obj )


def _GetCompleterForRequestData( request_data ):
  completer_target = request_data.get( 'completer_target', None )

  if completer_target == 'identifier':
    return _server_state.GetGeneralCompleter().GetIdentifierCompleter()
  elif completer_target == 'filetype_default' or not completer_target:
    return _server_state.GetFiletypeCompleter( request_data[ 'filetypes' ] )
  else:
    return _server_state.GetFiletypeCompleter( [ completer_target ] )


def ServerShutdown():
  def Terminator():
    if wsgi_server:
      wsgi_server.shutdown()

  # Use a separate thread to let the server send the response before shutting
  # down.
  StartThread( Terminator )


def ServerCleanup():
  if _server_state:
    _server_state.Shutdown()
    extra_conf_store.Shutdown()


def SetHmacSecret( hmac_secret ):
  global _hmac_secret
  _hmac_secret = hmac_secret


def UpdateUserOptions( options ):
  global _server_state

  if not options:
    return

  # This should never be passed in, but let's try to remove it just in case.
  options.pop( 'hmac_secret', None )
  user_options_store.SetAll( options )
  _server_state = server_state.ServerState( options )


def KeepSubserversAlive( check_interval_seconds ):
  def Keepalive( check_interval_seconds ):
    while True:
      time.sleep( check_interval_seconds )

      LOGGER.debug( 'Keeping subservers alive' )
      loaded_completers = _server_state.GetLoadedFiletypeCompleters()
      for completer in loaded_completers:
        completer.ServerIsHealthy()

  StartThread( Keepalive, check_interval_seconds )
