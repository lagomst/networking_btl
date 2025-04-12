import socket
import struct
import logging
from threading import Lock, Thread
from Downloader2 import Downloader
from Upload import Upload

logging.basicConfig(level=logging.INFO)

class P2PConnection:
    def __init__(self, torrent_file_path, our_peer_id="192.168.56.1", peerList=[], port=9000):
        self.lock = Lock()
        self.our_peer_id = our_peer_id 
        self.peerList = peerList
        self.torrent_file_path = torrent_file_path
        self.port = port
        self.isEnoughPiece = False
        self.number_of_bytes_downloaded = 0
        self.uploader = Upload(torrent_file_path, r'DownloadFolder/mapping_file.json', our_peer_id)
        self.downloader = Downloader(self.torrent_file_path, self.our_peer_id, self.peerList, self.uploader, self.number_of_bytes_downloaded, self.port)
        self.uploader._set_downloader(self.downloader)

    def start_downloading(self):
        self.downloader._download()

    def listen_for_peers(self):
        """Continuously listens for incoming peer connections."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind(('', self.port))
                server_socket.listen(5)

                while True:
                    conn, addr = server_socket.accept()
                    Thread(target=self.handle_incoming_peer, args=(conn, addr)).start()
        except socket.error as e:
            logging.error(f"Error while listening for peers: {e}")

    def handle_incoming_peer(self, conn, addr):
        """Handles an incoming peer connection."""
        try:
            self.uploader.upload_flow(conn)
        except (socket.error, struct.error) as e:
            logging.error(f"Error handling peer {addr}: {e}")
        finally:
            conn.close()