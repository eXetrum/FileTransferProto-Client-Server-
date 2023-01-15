# -*- coding: utf-8 -*-

import sys        # Using for retrive and parse command arguments
import socket     # Socket package, using for handle TCP connections
import time       # Get current timestamp
import datetime   # Get current datetime combined with timestamp (using both for gettimestamp() method)
###############################################################
CRLF = '\r\n'     # End of line separator using in FTP protocol
DEFAULT_PORT = 21 # Default ftp server port
###############################################################
# Show usage format. If we run script without apropriate arguments then script will show up usage info
def print_usage():
    print("<host/ip> <log file name> <remote port=DEFAULT_PORT>")
###############################################################
# Base Ftp client exception class
class FtpClientException(Exception):
    # Constructor: accept error message
    def __init__(self, message):
        super(FtpClientException, self).__init__(message)
    # Overload __str__ method to convert FtpClientException objects to string, with allow us to use print function
    def __str__(self):
        return self.message 
###############################################################
# FTP client class. With allow us to connect to the server, send and receive messages
class FtpClient:
    """
    Constructor accept server host, 
    server port and filename (actualy filepath) for log file
    """
    def __init__(self, remote_host, remote_port, log_file_name):
        # log file handler 
        self.f = None
        # Copy remote host, port, and filename
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.log_file_name = log_file_name
        # Control socket. Will be used for send/receive commands to/from remote server.
        self.control_socket = None
        # Data socket. Used for data connection:
        # in pasive mode we will use this socket for outcome connection
        # in active mode - as server socekt, for listen income connection from remote server
        self.data_socket = None    
        # this variable will be used for store connection parameters for pasive mode
        self.pasv = None
        # this variable will be used for store socket after accepted incoming connection from the server in active mode
        self.actv = None
        # Initialy no pasive, no active mode
        self.pasive_mode, self.active_mode = False, False
        # Validate argumens, remote_host should be valid value so we can obtain ip address,
        # log_file_name should be valid filename, 
        # port should be a positive integer
        try:
        # Try to resolve hostname
            self.remote_ip = socket.gethostbyname(remote_host)
            # Parse remote port
            self.remote_port = int(remote_port)
            if(self.remote_port <= 0):
                raise ValueError
            # Finally open log file with append mode
            self.f = open(log_file_name, "a+")
        # Rerise exceptions
        except(socket.error):
            raise FtpClientException("Resolve hostname error")
        except(IOError):
            raise FtpClientException("Cannot open/create log file")
        except(ValueError):
            raise FtpClientException("Remote port should be a positive integer")
    ###############################################################
    # Override __enter__ method with allow us to use object of our class in "with" statements (automaticly close resource: sockets, files)
    def __enter__(self):
        return self
    ###############################################################
    # This will be called after leave "with" statement
    def __exit__(self, exc_type, exc_value, traceback):
        # Close control connection and release socekt resource
        self.closeControlConnection()
        # Close data connection and release socket resource
        self.closeDataConnection()
        # Close log file on exit
        if self.f != None: 
            self.log("Close log file.")
            self.f.close()
    ###############################################################
    def closeControlConnection(self):
        if self.control_socket != None:
            self.log("Close control connection.")
            self.control_socket.close()
        self.control_socket = None
    ###############################################################
    # Close data connection and release resources
    def closeDataConnection(self):
        # If we close data connection in ACTIVE mode
        if self.active_mode:
            if self.data_socket != None:
                self.log("Close listen socket.")
                self.data_socket.close()   
            if self.actv != None:
                self.log("Close accepted socket.")
                self.actv.close()
        # Otherwise may be PASIVE mode
        elif self.pasive_mode:
            if self.data_socket != None:
                self.log("Close listen socket.")
                self.data_socket.close()   
        # Assign variables None
        self.actv, self.pasv, self.data_socket = None, None, None
    ###############################################################
    # Return string of current time stamp
    def get_timestamp(self):
        # Get current date/time and convert to string using specified format
        return datetime.datetime.now().strftime('%m/%d/%Y %H:%M:%S.%f')
    ###############################################################
    # Log message to console and logfile
    def log(self, message):
        # Get timestamp
        ts = self.get_timestamp()
        # Print to console
        print( ts + " " + message )
        # Append to lof file
        self.f.write(ts + " " + message + "\n")
    ###############################################################
    # Create connection to remote ftp server using remote_ip, remote_port pairs
    def openConnection(self):
        # Prevent open new connection without close old
        self.closeControlConnection()
        self.closeDataConnection()
        # Try to make remote connection
        try:
            # Create control socket
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set timeout to 15 sec ( we dont want to wait forever )
            self.control_socket.settimeout(15)
            # Make log record about connection
            self.log("Connecting to %s (%s:%d)" % (self.remote_host, self.remote_ip, self.remote_port))
            # Connect to remote server
            self.control_socket.connect((self.remote_ip, self.remote_port))
            # Connection complete wait for 'Wellcome message' from server
            response = self.receiveAnswer("")
            # If everything okay server should send us status code == 220
            if response["code"] != 220:
                self.log("Received bad \"Hello Header\"")
                raise FtpClientException("Received bad \"Hello Header\"")
        # Handle socket exception
        except(socket.error):
            raise FtpClientException("Unable connect to %s (%s:%d)" % (self.remote_host, self.remote_ip, self.remote_port))    
    ###############################################################
	# Login to the remote ftp server with login/pass pairs
    def login(self, user_login, user_pass):
        # To proceed login operation we must already connected
        if self.control_socket == None:
            raise FtpClientException("Cannot login without open connection")
        # Make log records about login/password pairs
        self.log("Login: " + user_login)
        self.log("Password: " + user_pass)
        # Send USER command to the ftp server with user_login string
        self.sendCommand("USER" + " " + user_login)
        # Read responce
        response = self.receiveAnswer("USER")
        # Expect code 331 or 220, otherwise server reject user_login
        if response["code"] != 331 and response["code"] != 220:
            raise FtpClientException("Server not accept username: " + user_login)
        # If user accepted, send PASS command with user password
        self.sendCommand("PASS" + " " + user_pass)	
        # Read responce
        response = self.receiveAnswer("PASS")
        # Expected status code 230 or 220, otherwise login/password pairs dont accepted by server
        if response["code"] != 230 and response["code"] != 220:
            raise FtpClientException("Server not accept username/password pair: " + user_login + " / " + user_pass)
    ###############################################################
    # Read data from socket [sock]
    def readFrom(self, sock):
        # Result buffer and current character
        buffer, char = '', ' '
        try:
            # Read from the [sock] socket while next char not empty and full data not end with CRLF
            while char != '' and not buffer.endswith(CRLF):
                # Next character
                char = sock.recv(1)
                # Append character to the result buffer
                buffer += char
        # Handle socket errors
        except(socket.error):
            buffer = '500 '
            raise FtpClientException("Unexpected error while read from socket")
        # Remove CRLF characters (at left/right positions) from the result buffer
        return buffer.strip(CRLF)
    ###############################################################
    # Send command to remote ftp server
    def sendCommand(self, command):
        # Retrive arguments
        args_pos, args = command.find(" "), ""
        if args_pos != -1: 
            args = command[args_pos + 1:]
            command = command[:args_pos]
        # If we want to send "PORT" command then we must prepare listen socket for data connection
        if command == "port":
            # If we have already created listen socket -> close it
            self.closeDataConnection()
            # Turn on active mode
            self.pasive_mode, self.active_mode = False, True
            # Get machine current ip
            ip = socket.gethostbyname(socket.gethostname())
            # Create listen socket for incoming connections
            self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.data_socket.settimeout(15)
            # Bind to the current ip and random free port
            self.data_socket.bind((ip, 0))
            # Get port that socket binded at
            port = self.data_socket.getsockname()[1]
            # Start listen for inc connections
            self.data_socket.listen(0)
            # Create h1, h2 port pairs by PORT command format with is: 4 digit of ip and 2 digit of port
            h1, h2 = port // 256, port % 256
            ip = ip.split(".")
            ip += [h1, h2]
            # Result port arguments separated with ","
            args = ",".join(map(str, ip))
        elif command == "eprt":
            self.closeDataConnection()
            # Turn on active mode
            self.pasive_mode, self.active_mode = False, True
            # Get machine current ip
            ip = socket.gethostbyname(socket.gethostname())
            # Create listen socket for incoming connections
            self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_socket.settimeout(15)
            # Bind to the current ip and random free port
            self.data_socket.bind((ip, 0))
            # Get port that socket binded at
            print("EPRT: ", self.data_socket.getsockname())
            port = self.data_socket.getsockname()[1]
            # Start listen for inc connections
            self.data_socket.listen(0)
            # Result port arguments separated with "|"
            args = "|1|" + ip + "|" + str(port) + "|"
        # Send command to remove server
        self.log("Sent: " + command + " " + args)
        self.control_socket.send(command + " " + args + CRLF)
    ###############################################################
    # Receive command from remote ftp server
    def receiveAnswer(self, command):
        response = {"code" : None, "message" : None}
        buffer = ''
        # If last commad LIST
        if command.startswith("list"):
            # And if pasv command hpnd early
            if self.pasive_mode:
                # Try to make data connection to remote server
                try:
                    self.data_socket = socket.socket()
                    self.data_socket.settimeout(10)
                    self.data_socket.connect(self.pasv)
                    self.log("Data connection to %s %s established succefuly." % self.pasv)
                except(socket.error):
                    self.log("Unable open data connection")
        # Answer on RETR commad 
        elif command.startswith("retr"):
            # Retr in passive mode PASV/EPSV
            if self.pasive_mode and self.pasv != None:
                try:
                    self.data_socket = socket.socket()
                    self.data_socket.settimeout(10)
                    self.data_socket.connect(self.pasv)
                    self.log("Data connection to %s %s established succefuly." % self.pasv)
                except(socket.error):
                    self.log("Unable open data connection")
        # Read all response lines
        line, lines = '', []
        while not line.startswith("500") and line.find(" ") != 3:
            line = self.readFrom(self.control_socket)
            lines.append(line)
        # Result message from the server
        response["message"] = "\n".join(lines)
        self.log("Received: " + response["message"])
        # Parse status code
        line = lines[len(lines) - 1]
        # Split answer code and message
        try:
            response["code"] = int(line[:3])
        except:
            response["code"] = -1
        # Return obtained responce
        return response
    ###############################################################
    # Method for read answer after command LIST, using [sock] as "data socket"
    def readLIST(self, sock):
        line, lines = ' ', []
        # Read all lines
        while line != '':
            line = self.readFrom(sock)
            lines.append(line) 
        return "\n".join(lines)
    ###############################################################
    # Method for read answer on RETR command, using [sock] as "data socket"
    def readRETR(self, sock):
        # buffer - result received data
        # chunk - current received character
        # line, i - used for print out received bytes by 8 elements in each line
        buffer, chunk, line, i =  '', ' ', '', 0
        # Read data from socket until we reach no data (empty chunk)
        while chunk != '':
            chunk = sock.recv(1)
            # If we reach empty data - stop read
            if chunk == '': break
            # Append new byte to line
            line += "0x{:02x} ".format( ord(chunk) )
            # Time to show line of bytes ? (8 element in each line) -> then print line
            if (i + 1) % 9 == 0:
                print("\t" + line)
                # Empty line, zero byte counter
                line, i = '', 0
            # Next byte
            i += 1
            # Append character to result buffer
            buffer += chunk
        # Return received data
        return buffer
    ###############################################################
    # Parse response obtained from the server
    def parseResponse(self, response, command):
        # PASV
        if command.startswith("pasv"):
            # Expected 227 code
            if response["code"] == 227:
                # Parse response message for understand port/ip information for data connection
                args = response["message"]
                args = args[args.find(",") - 3 : ].strip(' ()\r\n*.;|')
                temp = args.split(",")
                temp = map(lambda x : str(x).strip(' ()\r\n*|'), temp)
                ip = ".".join(temp[:4])
                port = int(temp[4]) * 256 + int(temp[5])
                self.pasv = (ip, port)
                self.pasive_mode = True
            else: # Otherwise PASV fail
                self.pasv = None
                self.pasive_mode = False
        # EPSV
        elif command.startswith("epsv"):
            # Expected 229
            if response["code"] == 229:
                # Parse EPSV result
                args = response["message"]
                args = args[args.find("|") + 1 : ].strip(' ()\r\n*.;')
                ip = self.remote_ip
                port = int(args.strip("|"))
                self.pasv = (ip, port)
                self.pasive_mode = True
            else: # Otherwise EPSV command failure
                self.pasv = None
                self.pasive_mode = False
        # PORT
        elif command.startswith("port"):
            # Expected 200 code
            if response["code"] == 200:
                self.pasive_mode, self.active_mode = False, True
            else: 
                self.active_mode = False
                #self.sendCommand("226 Closing data connection.")
                self.data_socket.close()
                self.data_socket = None
        # EPRT
        elif command.startswith("eprt"):
            # Expected 200 code
            if response["code"] == 200:
                self.pasive_mode, self.active_mode = False, True
            else: 
                self.active_mode = False
                #self.sendCommand("226 Closing data connection.")
                self.data_socket.close()
                self.data_socket = None
        # Status file OK. Prepare data connection
        elif (response["code"] == 150 or response["code"] == 125) and (command.startswith("list") or command.startswith("retr")):
            if self.data_socket == None:
                # Read post message
                buffer = self.readFrom(self.control_socket)
                self.log("Received: " + buffer)
                return
            # Active mode
            if self.active_mode:
                # Try to accept connection from remote server
                try:
                    (conn, addr) = self.data_socket.accept()
                    self.actv = conn
                    self.log("Accepted connection: " + str(addr))
                    # Turn socket into blocking mode
                    self.actv.setblocking(1)
                    # Active mode and LIST command
                    if command.startswith("list"):
                        buffer = self.readLIST(self.actv)
                        self.log("Received: " + str(len(buffer)) + " bytes \n")
                        self.log("\n" + buffer)
                    # Active mode and RETR command
                    elif command.startswith("retr"):
                        filename = command[5:]
                        f = open(filename, "wb")
                        buffer = self.readRETR(self.actv)
                        # Log info about file length
                        self.log("Received: file: \"" + filename + "\" " + str(len(buffer)) + " bytes \n")
                        # Flush buffer into file
                        f.write(buffer)
                        f.close()                        
                # Handle exceptions
                except socket.error as e:
                    self.log("Active mode fail: " + str(e))
                # Close accepted socket
                if self.actv != None: self.actv.close()
                self.actv = None
                # Turn off active mode
                self.active_mode = False
            # Pasive mode
            elif self.pasive_mode:
                # Try to read from data socket in pasive mode
                try:
                    # Pasive mode and LIST command
                    if command.startswith("list"):
                        buffer = self.readLIST(self.data_socket)
                        self.log("Received: " + str(len(buffer)) + " bytes \n")
                        self.log("\n" + buffer)
                    # Passive mode and RETR command
                    elif command.startswith("retr"):
                        buffer = self.readFrom(self.control_socket)
                        self.log("Received: " + buffer)
                        filename = command[5:]
                        f = open(filename, "wb")
                        buffer = self.readRETR(self.data_socket)
                        # Log info about file length
                        self.log("Received: file: \"" + filename + "\" " + str(len(buffer)) + " bytes \n")
                        # Flush buffer into file
                        f.write(buffer)
                        f.close()
                # Handle exceptions
                except socket.error as e:
                    self.log("Pasive mode fail: " + str(e))
                # Turn off pasive mode
                self.pasv = None
                self.pasive_mode = False
            # 150 CODE END
            # Close data connection and release socket resources
            self.closeDataConnection()
            # Read post message
            buffer = self.readFrom(self.control_socket)
            self.log("Received: " + buffer)
###############################################################        
# Main function
def main():
    # Receive command line arguments
    args = sys.argv[1:]
    # We can start only with 2 or 3 arguments ([host, logfile]  OR  [host, logfile, port])
    if(len(args) != 2 and len(args) != 3):
        print_usage()
        return None
    # Get command line arguments; remote port first set to DEFAULT_PORT
    remote_host, log_file_name, remote_port = args[0], args[1], DEFAULT_PORT    
    # Check if user specified remote port
    if(len(args) == 3): remote_port = args[2]
    # Create and use FtpClient object
    with FtpClient(remote_host, remote_port, log_file_name) as ftp:
        try:
            # Create connection to ftp server
            ftp.openConnection()
            user_login = raw_input("Login: ")
            user_pass  = raw_input("Password: ")
            # Login to the ftp server
            ftp.login(user_login, user_pass)
            # String for user command
            command = ""
            while not command.startswith("quit"):
                # Get command from user
                command = str(raw_input(">")).strip().lower()
                # Check if command not empty
                if len(command) == 0: continue
                # Send command to ftp server
                ftp.sendCommand(command)
                # Receive answer from the server
                response = ftp.receiveAnswer(command)
                # Post process answer (parse or other moves)
                ftp.parseResponse(response, command)
        # Handle exceptions
        except FtpClientException as e:
            ftp.log("ERROR: " + str(e))
###############################################################
# if we use this not as module -> just run main function
if __name__ == "__main__":
	main()
###############################################################