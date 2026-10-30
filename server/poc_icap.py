# ==============================================================================
# Filename:         poc_icap.py
# Description:      ICAP server for capturing HTTP requests and responses
# Author:           Adam A https://github.com/atariq11700
# Date Created:     2026-10-29
# License:          AGPL-3.0
# ==============================================================================

import argparse
import collections
import collections.abc
from datetime import datetime, timezone
import os
import posixpath
import re
import socketserver
from contextlib import suppress
from email.message import Message
from urllib.parse import unquote, urlsplit

import pyicap


collections.Callable = collections.abc.Callable

RESPONSE_CAPTURE_BLACKLIST = {
    #("hostname", "endpoint")
}

REQUEST_CAPTURE_BLACKLIST = {
    #("hostname", "endpoint")
}


def safe_name(name):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name).strip(".")[:120] or "response"


def response_name(url, headers):
    disposition = Message()
    if b'content-disposition' in headers:
        disposition['Content-Disposition'] = headers[b'content-disposition'][0].decode('latin-1')
    path_name = posixpath.basename(unquote(urlsplit(url).path))
    name = posixpath.basename(disposition.get_filename() or path_name or 'response')
    return safe_name(name)


class CaptureHandler(pyicap.BaseICAPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass

    def read_chunk(self):
        if not self.has_body or self.eob:
            self.eob = True
            return b''
        if not getattr(self, 'remaining_chunk', 0):
            line = self.rfile.readline(128)
            size, _, extension = line.partition(b';')
            if not line.endswith(b'\r\n'):
                raise ConnectionError('Incomplete ICAP chunk header')
            self.remaining_chunk = int(size.strip(), 16)
            if not self.remaining_chunk:
                self.ieof = extension.strip() == b'ieof'
                if self.rfile.read(2) != b'\r\n':
                    raise ConnectionError('Incomplete ICAP body')
                self.eob = True
                return b''
        chunk = self.rfile.read(min(self.remaining_chunk, 65536))
        if not chunk:
            raise ConnectionError('Incomplete ICAP chunk')
        self.remaining_chunk -= len(chunk)
        if not self.remaining_chunk and self.rfile.read(2) != b'\r\n':
            raise ConnectionError('Incomplete ICAP chunk trailer')
        return chunk

    def capture_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD, RESPMOD')
        self.set_icap_header(b'Service', b'Request capture, Response capture')
        self.set_icap_header(b'Preview', b'1024')
        self.set_icap_header(b'Allow', b'204')
        self.set_icap_header(b'Options-TTL', b'3600')
        self.set_icap_header(b'Encapsulated', b'null-body=0')
        self.send_headers()

    def capture_RESPMOD(self):
        if not self.has_body or not self.enc_res_status:
            self.no_adaptation_required()
            return

        url = self.enc_req[1].decode('latin-1') if self.enc_req else ''
        request_url = urlsplit(url)
        host_header = self.enc_req_headers.get(b'host', [b'unknown'])[0].decode('latin-1')
        domain = request_url.hostname or urlsplit('//' + host_header).hostname or 'unknown'
        if any((host.lower(), path) == (domain, request_url.path or '/')
               for host, path in RESPONSE_CAPTURE_BLACKLIST):
            self.no_adaptation_required()
            return
        filename = response_name(url, self.enc_res_headers)

        preview = []
        if self.preview is not None:
            while True:
                chunk = self.read_chunk()
                if not chunk:
                    break
                preview.append(chunk)
            if not self.ieof:
                self.cont()

        timestamp = self.capture_timestamp()
        directory = os.path.join(self.server.log_dir, 'downloads', safe_name(domain))
        path = os.path.join(directory, f'{timestamp}-{filename}')
        download = None
        try:
            os.makedirs(directory, mode=0o755, exist_ok=True)
            download = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), 'wb')
        except OSError as error:
            self.log_error('Cannot capture %s: %s', url, error)

        self.set_icap_response(200)
        self.set_enc_status(b' '.join(self.enc_res_status))
        for header, values in self.enc_res_headers.items():
            for value in values:
                self.set_enc_header(header, value)
        self.send_headers(has_body=True)
        complete = False
        captured = False
        try:
            for chunk in preview:
                self.write_chunk(chunk)
                if download:
                    try:
                        download.write(chunk)
                        captured = True
                    except OSError as error:
                        self.log_error('Cannot save %s: %s', path, error)
                        with suppress(OSError):
                            download.close()
                        download = None
                        with suppress(OSError):
                            os.unlink(path)
            while not self.ieof:
                chunk = self.read_chunk()
                if not chunk:
                    break
                self.write_chunk(chunk)
                if download:
                    try:
                        download.write(chunk)
                        captured = True
                    except OSError as error:
                        self.log_error('Cannot save %s: %s', path, error)
                        with suppress(OSError):
                            download.close()
                        download = None
                        with suppress(OSError):
                            os.unlink(path)
            self.write_chunk()
            complete = True
        finally:
            if download:
                try:
                    download.close()
                except OSError as error:
                    self.log_error('Cannot finish %s: %s', path, error)
                    complete = False
                if complete and captured:
                    self.log_message('Saved %s from %s', path, url)
                else:
                    with suppress(OSError):
                        os.unlink(path)

    def capture_REQMOD(self):
        if not self.has_body:
            self.no_adaptation_required()
            return

        url = self.enc_req[1].decode('latin-1') if self.enc_req else ''
        request_url = urlsplit(url)
        host_header = self.enc_req_headers.get(b'host', [b'unknown'])[0].decode('latin-1')

        domain = (request_url.hostname or urlsplit('//' + host_header).hostname or 'unknown')
        if any((host.lower(), path) == (domain, request_url.path or '/') for host, path in REQUEST_CAPTURE_BLACKLIST):
            self.no_adaptation_required()
            return

        filename = response_name(url, self.enc_req_headers)
        timestamp = self.capture_timestamp()
        directory = os.path.join(self.server.log_dir, 'uploads', safe_name(domain))
        path = os.path.join(directory, f'{timestamp}-{filename}')
        preview = []

        if self.preview is not None:
            while True:
                chunk = self.read_chunk()
                if not chunk:
                    break
                preview.append(chunk)

            if not self.ieof:
                self.cont()

        self.set_icap_response(200)
        self.set_enc_request(b' '.join(self.enc_req))
        for header, values in self.enc_req_headers.items():
            for value in values:
                self.set_enc_header(header, value)
        self.send_headers(has_body=True)

        download = None
        complete = False
        captured = False
        try:
            os.makedirs(directory, mode=0o755, exist_ok=True)
            download = os.fdopen(
                os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o644
                ),
                'wb'
            )
        except OSError as error:
            self.log_error('Cannot capture %s: %s', url, error)

        total_size = 0
        try:
            for chunk in preview:
                self.write_chunk(chunk)
                total_size += len(chunk)

                if download:
                    try:
                        download.write(chunk)
                        captured = True
                    except OSError as error:
                        self.log_error('Cannot save %s: %s', path, error)

                        with suppress(OSError):
                            download.close()

                        download = None
                        with suppress(OSError):
                            os.unlink(path)

            while not self.ieof:
                chunk = self.read_chunk()
                if not chunk:
                    break

                self.write_chunk(chunk)
                total_size += len(chunk)
                if download:
                    try:
                        download.write(chunk)
                        captured = True

                    except OSError as error:
                        self.log_error('Cannot save %s: %s', path, error)

                        with suppress(OSError):
                            download.close()

                        download = None
                        with suppress(OSError):
                            os.unlink(path)

            self.write_chunk()
            complete = True

        finally:
            if download:
                try:
                    download.close()
                except OSError as error:
                    self.log_error('Cannot finish %s: %s', path, error)
                    complete = False

            if complete and captured and total_size > 0:
                self.log_message(
                    'Saved request body (%s bytes): %s from %s',
                    total_size,
                    path,
                    url
                )
            else:
                with suppress(OSError):
                    os.unlink(path)

    def capture_timestamp(self):
        ts_str = self.headers.get(b'X-Request-Timestamp', b'').decode('utf-8')
        try:
            if not ts_str:
                raise TypeError('Timestamp header is empty')
            
            epoch_seconds = float(ts_str)
            return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()
        
        except (TypeError, ValueError):
            return datetime.now(timezone.utc).isoformat()

class CaptureServer(socketserver.ThreadingMixIn, pyicap.ICAPServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description='Stream and save ICAP RESPMOD response bodies')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=1344)
    parser.add_argument('--log-dir', required=True)
    args = parser.parse_args()
    with CaptureServer((args.host, args.port), CaptureHandler) as server:
        server.log_dir = args.log_dir
        print(f'[ICAP] Listening on {args.host}:{args.port}', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()