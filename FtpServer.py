# -*- coding: utf-8 -*-
import sys        # Using for retrive and parse command arguments
import socket     # Socket package, using for handle TCP connections
import select     # Select ready socket
import time       # Get current timestamp
import datetime   # Get current datetime combined with timestamp (using both for gettimestamp() method)
import threading  # Separate threads for each client
import stat, os   # List of files/dirs

lock = threading.Lock()
serverStartEvent = threading.Event()
serverStopEvent  = threading.Event()
###############################################################
CRLF          = '\r\n'            # End of line separator using in FTP protocol
DEFAULT_PORT  = 21                # Default ftp server port
CONFIG_FILE   = "ftpserverd.conf" # Server configuration file
ACCOUNTS_FILE = "users.db"        # Default filename for file that store user logins/passwords
ROOT_FOLDER   = "Public"          # Default server folder. (clients work with this folder as root folder)
###############################################################
# Show usage format. If we run script without apropriate arguments then script will show up usage info
def print_usage():
    print("<log file name> <server port>")
###############################################################
# Base Ftp server exception class
############################################################### 
class FtpServerException(Exception):
    # Constructor: accept error message
    def __init__(self, message):
        super(FtpServerException, self).__init__(message)
    # Overload __str__ method to convert FtpServerException objects to string, with allow us to use print function
    def __str__(self):
        return self.message
############################################################### 
# Client as thread children
############################################################### 
class Client(threading.Thread):
    # Ctor accepted pair (client socket, remote address) that return accept method 
    def __init__(self, (sock, addr), loger, accounts, config):
        threading.Thread.__init__(self)
        # Client socket (control connection)
        self.sock = sock
        # Save ip,port pair where client come from
        self.addr = addr
        # Initialy server not running
        self.running = False
        # Set logger function
        self.log = loger
        # Save account dict
        self.accounts = accounts
        # Save config dict
        self.config = config
        # User not logged yet
        self.loged = False
        # User command is not specifed
        self.user = False
        # Current virtual path
        self.cur_dir = "/"
        # Absolute path to "server folder"
        self.ROOT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), ROOT_FOLDER)
        # Client name pair ip:port
        self.CLIENT_NAME = str.format("%s %d" % addr)
        self.data_socket = None
        self.actv = None
        self.pasv = None
        # Brute-force protection
        self.brute_force = {"attempts" : 0, "username" : None}
        # Max 3 wrong attempts before closing control connection
        self.max_brute_attemps = 3
    ############################################################### 
    # Override base class "run" method
    def run(self):
        # Initialy we toggle running mark 
        self.running = True
        # Send welcome message to client
        self.sendCommand("220 Welcome message")
        # Main receive/response loop
        while self.running:
            # Select socket that ready to read/write (last param -> timeout 1 sec)
            _in, _out, _exc = select.select([self.sock,], [self.sock,], [self.sock,], 1)
            for s in _in:
                if s != self.sock: continue
                try:
                    # Set client socket to blocking mode
                    self.sock.setblocking(1)
                    # Read command from client
                    data = self.readFrom(self.sock)
                    # Remove blocking settings
                    self.sock.setblocking(0)
                    # Proceed client command
                    if not data: self.close_connection()
                    else: self.parseResponse(data)                       
                # Handle socket errors
                except socket.error, (errorCode, message):
                    if errorCode != 10035:
                        self.log("socket.error: " + str(errorCode))
                    self.close_connection()
    ###############################################################
    # Close control and data connections (will be called when thread stop)
    def close_connection(self):
        if self.running == False: return
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            self.sock = None
            self.closeDataConnection()
        except:
            self.log("Error occured while close connection for %s" % self.CLIENT_NAME)
        self.log("Disconnected: %s %d" % self.addr)
    ###############################################################
    def closeDataConnection(self):
        # Try to close data socket
        try:
            if self.data_socket != None:
                self.data_socket.close()
                self.data_socket = None
        except socket.error:
            self.log("Error while close data_socket")
        # Try to close socket from active mode
        try:
            if self.pasv != None: self.pasv.close()
        except:
		    self.log("Error while close active mode socket")
        self.pasv = None
        self.actv = None
    ###############################################################
    # Read data from socket [sock]
    def readFrom(self, sock):
        # Result buffer and current character
        buffer, char = '', ' '
        # Read from the [sock] socket while next char not empty and full data not end with CRLF
        while char != '' and not buffer.endswith(CRLF):
            # Next character
            char = sock.recv(1)
            # Append character to the result buffer
            buffer += char
        # Remove CRLF characters (at left/right positions) from the result buffer
        return buffer.strip(CRLF)
    ################################################################
    # Convert virtual client path (PWD) to absolute path
    def virtualToReal(self):
        return os.path.normpath(self.ROOT_PATH + "/" + self.cur_dir)
    ################################################################
    # Proceed client command
    def parseResponse(self, data):
        # Remove trash symbols
        data = data.strip('\r\n \'\"')
        # Convert to lowercase
        cmdLower = str.lower(data)
        # Make log record
        self.log("Received from %s %d: %s" % (self.addr + (data, )) )
        # Proceed commands
        if cmdLower == "quit":
            self.sendCommand("221 Goodbye, closing seesion.")
            self.close_connection()
            return
        if cmdLower == "help":
            message  = "214-The following commads are recognized: \r\n"
            message += "USER, PASS, CWD, CDUP, QUIT, PASV, EPSV, PORT, RETR, PWD, LIST, HELP"
            message += "214 End"
            self.sendCommand(message)
            return
        # USER
        if str.lower(data).startswith("user"):
            self.loged = False
            self.user = False
            params = data.split()
            if len(params) == 1:
                self.sendCommand("530 Invalid user name.")
                return
            # Parse username
            self.user = params[1].strip(CRLF)
            # Brute-force protection
            if self.brute_force["username"] == None: 
                self.brute_force["username"] = self.user
                self.brute_force["attempts"] = 0                
            # Check if we have record for this user
            if self.accounts.get(self.user) == None:
                self.sendCommand("530 Invalid user name.")
                self.user = False
                return
            self.sendCommand("331 User name okay, need password.")
            return
        # PASS
        elif cmdLower.startswith("pass"):
            if self.loged:
                self.sendCommand("503 Bad sequence of commands.")
                return
            if not self.user:
               self.sendCommand("530 Username not specifed.")
               return
            params = data.split()
            if len(params) == 1:
                self.sendCommand("530 Not logged in.")
                self.user = False
                return
            # Parse user password
            password = params[1].strip(CRLF)
            # Compare passwords
            if self.accounts[self.user] != password:
                self.brute_force["attempts"] = self.brute_force["attempts"] + 1
                # Brute-force detection
                if self.brute_force["username"] == self.user and self.brute_force["attempts"] == self.max_brute_attemps:
                    self.sendCommand("421 Service not available, closing control connection. (Brute-force detection)")                
                    self.log("Brute-force detected: %s" % self.CLIENT_NAME)
                    self.close_connection()
                    return
                # Otherwise just said that password is not correct
                self.sendCommand("530 Bad password.")
                self.user = False
                return
            # Password accepted
            self.loged = True
            self.sendCommand("230 User logged in, proceed.")
            return
        # For commands all down AUTH Required !!!			
        if not self.loged:
            self.sendCommand("530 Authentification required.")
            return
        # PWD
        if cmdLower == "pwd":
            self.sendCommand("257 \"" + self.cur_dir + "\" us current directory.")
            return
        # CDUP
        elif cmdLower == "cdup":
            if not self.cur_dir == "/":
                # Get absolute path
                p = os.path.normpath(self.virtualToReal())
                # Go dir UP
                p = os.path.abspath(os.path.join(p, '..'))
                # Prevent move up from root directory
                pos = p.find(self.ROOT_PATH)
                if pos == -1: # To far away -> lock into root dir
                    self.cur_dir = "/"
                else:
                    # Cutoff last part
                    self.cur_dir = p[pos + len(self.ROOT_PATH):]
                    if self.cur_dir == "": self.cur_dir = "/"
            self.sendCommand("250 Directory changed to \"" + self.cur_dir + "\"")
        # CWD
        elif cmdLower.startswith("cwd"):
            # Command require one argument
            params = cmdLower.split()
            if len(params) == 1:
                self.sendCommand("501 Syntax error in parameters or arguments.")
                return
            # Folder name can be with spaces so construct string back but cutoff first part (command="cwd")
            folder = ' '.join(params[1:])
            abs_path = ''
            if folder.startswith("/") or folder.startswith("\\"):
                abs_path = os.path.normpath(self.ROOT_PATH + "/" + folder)
                self.cur_dir = os.path.normpath(folder)
            else:
                abs_path = self.virtualToReal()
                abs_path = os.path.normpath(abs_path + "/" + folder)
                self.cur_dir = os.path.normpath(self.cur_dir + "/" + folder)
            if not os.path.isdir(abs_path) or not os.path.exists(abs_path):
                self.sendCommand("550 " + folder + ": No such file or directory.")
                return            
            self.cur_dir = '/' + self.cur_dir.replace('\\', '/').lstrip('/')
            self.sendCommand("250 Directory changed to \"" + self.cur_dir + "\"")
        # LIST
        elif cmdLower.startswith("list"):
            # List command require transmition via data connection. So passive or active mode should be enabled before LIST
            if self.actv == None and self.pasv == None:
                self.sendCommand("426 Data connection not specified.  A PORT/EPRT or PASV/EPSV command must be issued before executing this operation.")
                return
            # List can be with params
            args, params = '', cmdLower.split(' ')
            if len(params) > 1:
                # Get LIST arguments
                args = ' '.join(params[1:])
            # Send files list using active mode
            if self.actv:
                try:
                    # Get saved params
                    ip, port, ver = self.actv
                    # If PORT or EPRT but version 1 -> using ipv4
                    if ver == 1:
                        self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.data_socket.settimeout(15)
                        self.data_socket.connect((ip, port))
                    else: # Otherwise ipv6
                        self.data_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        self.data_socket.settimeout(15)
                        self.data_socket.connect((ip, port))
                    self.sendCommand("150 Opening ASCII mode data connection.")
                    # Get files list
                    m = self.getLIST(args)
                    self.log("Sent via data connection to %s %d:\n%s" % (self.addr + (m, )) )
                    # Send to client
                    self.data_socket.send(m + CRLF)
                    # Send post message
                    self.sendCommand("226 Transfer complete.")
                except socket.error as e:
                    self.log("Active mode for %s %d.\nFailed with error: %s" % (self.addr + (str(e), ) ))
                    self.sendCommand("421 Active mode failed")
            # Send files list using passive mode
            elif self.pasv:
                try:
                    self.sendCommand("150 Opening ASCII mode data connection.")
                    # Accept remote connection
                    (conn, addr) = self.data_socket.accept()
                    self.pasv = conn
                    self.log("For client %s %d, accepted data connection %s %d: " % (self.addr + addr))
                    # Turn socket into blocking mode
                    self.pasv.setblocking(1)
                    # Get files list
                    m = self.getLIST(args)
                    self.log("Sent via data connection to %s %d:\n%s" % (self.addr + (m, )) )
                    # Send list to the client
                    self.pasv.send(m + CRLF)
                    # Send post message
                    self.sendCommand("226 Transfer complete.")
                except socket.error as e:
                    self.log("Pasive mode for %s %d.\nFailed with error: %s" % (self.addr + (str(e), ) ))
                    self.sendCommand("421 Passive mode failed")
            # Close data connection
            self.closeDataConnection()
        # RETR
        elif cmdLower.startswith("retr"):
            if self.actv == None and self.pasv == None:
                self.sendCommand("426 Data connection not specified.  A PORT/EPRT or PASV/EPSV command must be issued before executing this operation.")
                return
            # RETR command require argument
            args, params = '', cmdLower.split(' ')
            if len(params) == 1:
                self.sendCommand("501 Syntax error in parameters or arguments.")
                # Cleanup data socket
                self.closeDataConnection()
                return
            # Grab command argument
            args = ' '.join(params[1:])
            # Active mode
            if self.actv:
                try:
                    # Get connection params
                    ip, port, ver = self.actv
                    # Create data socket and connect using ipv4 prot
                    if ver == 1:
                        self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.data_socket.settimeout(15)
                        self.data_socket.connect((ip, port))
                    else: # Otherwise use ipv6
                        self.data_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        self.data_socket.settimeout(15)
                        self.data_socket.connect((ip, port))
                    # Send "prepare" message
                    self.sendCommand("150 Opening ASCII mode data connection.")
                    # Parse filename
                    filename = args.strip(' \r\n.,')
                    # Construct absolute path to file
                    filepath = os.path.join(self.virtualToReal(), filename)
                    # Check if file exists
                    if not os.path.exists(filepath):
                        # If no -> send to client bad news
                        self.sendCommand("501 File Not found.")
                        self.log("File not found to %s %d:\n%s" % (self.addr + (m, )))
                    else: # Otherwise open file in binary mode, read and send via data connection
                        f = open(filepath, "rb")
                        data = f.read()
                        f.close() 
                        # Send file data
                        self.data_socket.send(data)
                        # Make log record
                        self.log("Sent via data connection to %s %d:\n%s" % (self.addr + (filepath, )) )
                        # Send post message
                        self.sendCommand("226 Transfer complete.")
                except socket.error as e:
                    # Something wrong -> make log record and send to client bad news
                    self.log("Active mode for %s %d.\nFailed with error: %s" % (self.addr + (str(e), ) ))
                    self.sendCommand("421 Active mode failed")
            # Passive mode
            elif self.pasv:
                try:
                    self.sendCommand("150 Opening ASCII mode data connection.")
                    # Accept remote data connection
                    (conn, addr) = self.data_socket.accept()
                    self.pasv = conn
                    self.log("For client %s %d, accepted data connection %s %d: " % (self.addr + addr))
                    # Turn socket into blocking mode
                    self.pasv.setblocking(1)					
                    self.sendCommand("150 Opening ASCII mode data connection.")
                    # Parse filename
                    filename = args.strip(' \r\n.,')
                    # Construct absolute path to retrive file
                    filepath = os.path.join(self.virtualToReal(), filename)
                    # File should exists
                    if not os.path.exists(filepath):
                        self.sendCommand("501 File Not found.")
                        self.log("File not found to %s %d:\n%s" % (self.addr + (m, )))
                    else:
                        # Open file in binary mode, read and send
                        f = open(filepath, "rb")
                        data = f.read()
                        f.close()
                        self.pasv.send(data)
                        # Make log record
                        self.log("Sent via data connection to %s %d:\n%s" % (self.addr + (filepath, )) )
                        # Send post message
                        self.sendCommand("226 Transfer complete.")
                except socket.error as e:
                    self.log("Pasive mode for %s %d.\nFailed with error: %s" % (self.addr + (str(e), ) ))
                    self.sendCommand("421 Passive mode failed")
            # Cleanup data socket
            self.closeDataConnection()
        # PASV
        elif cmdLower.startswith("pasv"):
            # Check if the server support pasv_mode
            if self.config["pasv_mode"] == "NO":
                self.sendCommand("500 PASV/EPSV (Passive Mode/Extended Passive Mode) is not supported. Use PORT/EPRT instead of this")
                return
            # Try to open listen data connection
            try:
                self.closeDataConnection()
                # Create listen socket for incoming connections
                self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #self.data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.data_socket.settimeout(15)
                ip = self.addr[0]
                # Bind to the current ip and random free port
                self.data_socket.bind((ip, 0))
                # Get port that socket binded at
                port = self.data_socket.getsockname()[1]
                # Start listen for inc connections
                self.data_socket.listen(0)
                # Create h1, h2 port pairs by PASV command format with is: 4 digit of ip and 2 digit of port
                h1, h2 = port // 256, port % 256
                ip = ip.split(".")
                ip += [h1, h2]
                # Result port arguments separated with ","
                args = ",".join(map(str, ip))
                self.pasv = (ip, port)
                self.sendCommand("227 Entering Passive Mode " + args)
            except Exception as e:
                self.log("Entering passive mode FAIL with errorCode: " + str(e))
                self.sendCommand("500 Passive mode failed") #421 ?
        # EPSV
        elif cmdLower.startswith("epsv"):
            # Check if the server support pasv_mode
            if self.config["pasv_mode"] == "NO":
                self.sendCommand("500 PASV/EPSV (Passive Mode/Extended Passive Mode) is not supported. Use PORT/EPRT instead of this")
                return
            try:
                self.closeDataConnection()
                # Create listen socket for incoming connections
                self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #self.data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.data_socket.settimeout(15)
                ip = self.addr[0]
                # Bind to the current ip and random free port
                self.data_socket.bind((ip, 0))
                # Get port that socket binded at
                port = self.data_socket.getsockname()[1]
                # Start listen for inc connections
                self.data_socket.listen(0)
                # Result port arguments separated with ","
                self.pasv = (ip, port)
                self.sendCommand("229 Entering Extended Passive Mode (|||" + str(port) + "|)")
            except Exception as e:
                self.log("Entering extended passive mode FAIL with errorCode: " + str(e))
                self.sendCommand("421 Extended passive mode failed") #421 ?
        # PORT
        elif cmdLower.startswith("port"):
            self.closeDataConnection()
            params = cmdLower.split(' ')
            # We should receive exacly 1 argument after space
            if len(params) == 1:
                self.sendCommand("501 Syntax error in parameters or arguments.")
                return
            # Check if the server support port_mode
            if self.config["port_mode"] == "NO":
                self.sendCommand("500 PORT/EPRT (Active Mode/Extended Active Mode) is not supported. Use PASV/EPSV instead of this")
                return
            # Try to parse PORT command arguments
            try:
                params = params[1].split(",")
                ip = ".".join(params[:4])
                port = int(params[4]) * 256 + int(params[5])
                # Prevent "bounce attacks" (rfc2 577)
                if port < 1024:
                    self.sendCommand("504 Command not implemented for that parameter")
                    self.log("Bounce-attack detected: %s, port=%d" % (self.CLIENT_NAME, port))
                    return
                # Check if remote ip changed -> aswell bounce attack 
                if ip != self.addr[0]:
                    self.sendCommand("504 Command not implemented for that parameter")
                    self.log("Bounce-attack detected: %s, constrol_host=%s != data_host=%s" % (self.CLIENT_NAME, self.addr[0], ip))
                    return
                self.actv = (ip, port, 1)
                self.sendCommand("200 PORT command successful.")
                #self.readFrom(self.data_socket)
            except:
                self.sendCommand("501 Syntax error in parameters or arguments.")
                self.data_socket = None
                self.actv = None
                return
        # EPRT
        elif cmdLower.startswith("eprt"):
            self.closeDataConnection()
            params = cmdLower.split()
            if len(params)== 1:
                self.sendCommand("501 Syntax error in parameters or arguments.")
                return
            # Check if the server support port_mode
            if self.config["port_mode"] == "NO":
                self.sendCommand("500 PORT/EPRT (Active Mode/Extended Active Mode) is not supported. Use PASV/EPSV instead of this")
                return
            # Try to parse EPRT arguments
            try:
                params = params[1].strip("|\r\n,.;").split("|")
                protVer, ip, port = params
                # Prevent "bounce attacks" (rfc2 577)
                if port < 1024:
                    self.sendCommand("504 Command not implemented for that parameter")
                    self.log("Bounce-attack detected: %s, port=%d" % (self.CLIENT_NAME, port))
                    return
                # Check if remote ip changed -> aswell bounce attack 
                if ip != self.addr[0]:
                    self.sendCommand("504 Command not implemented for that parameter")
                    self.log("Bounce-attack detected: %s, constrol_host=%s != data_host=%s" % (self.CLIENT_NAME, self.addr[0], ip))
                    return
                #
                self.actv = (ip, int(port), int(protVer))
                self.sendCommand("200 EPRT command successful.")
            except Exception as e:
                self.sendCommand("501 Syntax error in parameters or arguments.")
                self.data_socket = None
                self.actv = None
        # Command not implemented
        else:
            self.sendCommand("202 Not implemented")                      
    ################################################################
    # Construct response string for LIST command
    def getLIST(self, args):
        p = ''
        if args:
            p = os.path.normpath(self.ROOT_PATH + "/" + args)
        else:
            p = self.virtualToReal()
        names = os.listdir(p)
        message = ''
        for name in names:
            message = message + self.permissions( os.path.join(p, name) ) + " " + name + "\r\n"
        return message
    ################################################################
    # Send command to the remote client
    def sendCommand(self, cmd):
        if self.sock == None: return
        self.sock.setblocking(1)
        self.sock.send(cmd + CRLF)
        self.log("Sent to " + self.CLIENT_NAME + ": " + cmd)
        self.sock.setblocking(0)
    ################################################################
	# Return file permissions, owner username, group, last modification, filesize
    # This method is helper for "getLIST"
    def permissions(self, filename):
        st = os.stat( filename )
        mode = st.st_mode
        isDir = stat.S_ISDIR(mode)
        res = ''
        res += 'd' if isDir else '-'
        res += 'r' if stat.S_IRUSR & mode else '-'
        res += 'w' if stat.S_IWUSR & mode else '-'
        res += 'x' if not isDir and stat.S_IXUSR & mode else '-'
        res += 'r' if stat.S_IRGRP & mode else '-'
        res += 'w' if stat.S_IWGRP & mode else '-'
        res += 'x' if not isDir and stat.S_IXGRP & mode else '-'
        res += 'r' if stat.S_IROTH & mode else '-'
        res += 'w' if stat.S_IWOTH & mode else '-'
        res += 'x' if not isDir and stat.S_IXOTH & mode else '-'
        user, group = "user", "group"
        try:
            import pwd, grp
            user  = pwd.getpwuid(uid)[0]
            group = grp.getpwuid(gid)[0]
        except:
            pass
        d = time.strftime('%b %d %Y', time.gmtime(os.path.getmtime(filename)) )
        
        return str.format("%s   1 %-10s %-10s %10lu %s" % (res, user, group, st.st_size, d))        
########################################################################################################
# FTP server class. With allow us to handle client connections to the server, send and receive messages
########################################################################################################
class FtpServer:
    """
    Constructor accept server port and filename (actualy filepath) for log file
    """
    def __init__(self, log_file_name, server_port):
        # log file handler 
        self.f = None
        # Copy port, and filename
        self.port = server_port
        self.log_file_name = log_file_name
        self.config = {}
        self.accounts = {}
        # Create root folder for incoming clients
        if not os.path.isdir(ROOT_FOLDER) or not os.path.exists(ROOT_FOLDER):
            os.makedirs(ROOT_FOLDER)
        # Load and parse config file
        try:
            with open(CONFIG_FILE) as cfg:
                for line in cfg:
                    # Ignore comments and empty lines
                    if line.startswith("#") or len(line) == 0 or line == '\r' or line == '\n': continue
                    # Otherwise this is valid key->value pair, so we must append it to config dictionary
                    # First remove from left and right sides of the line "bad characters" -> " ", "\r", "\n"
                    line = line.strip("\r\n ")
                    # Next split to obtain key, value pair, using "=" as delimiter
                    # Split operation can be failed if file format is wrong so we must caught TypeError exception
                    key, value = list(map(lambda x : str(x).strip("\r\n "), line.split("=")))
                    # If lines occured with same key multiple time only last record is matter
                    self.config[key] = value.upper()
        except TypeError:
            raise FtpServerException("Error occured while reading config file: bad file format")
        except IOError as e:
            raise FtpServerException("Error occured while reading configuration file, error message: " + str(e))
        # Check config key values
        if "logdirectory" not in self.config: self.config["logdirectory"] = "logfiles"
        #if "numlogfiles" not in self.config: raise FtpServerException("Config error. \"numlogfiles\" record not found !")
        if "usernamefile" not in self.config: raise FtpServerException("Config error. \"usernamefile\" record not found !")
        if "port_mode" not in self.config and "pasv_mode" not in self.config: raise FtpServerException("Config error. \"port_mode\" and \"pasv_mode\" records not found (at least one should be in the cfg file)!")
        # Default values for settings that not shown in cfg file
        if "port_mode" not in self.config: self.config["port_mode"] = "NO"
        if "pasv_mode" not in self.config: self.coding["pasv_mode"] = "NO"
          
        active = ( self.config["port_mode"] == "YES" )
        pasive = ( self.config["pasv_mode"] == "YES" )
        if active == False and pasive == False: raise FtpServerException("Config error. At least one transfer mode should be enabled (port/pasv)")
        # Check if directory for logs is actualy directory and not file and if this directory exists -> otherwise throw an error
        if not os.path.isdir(self.config["logdirectory"]) or not os.path.exists(self.config["logdirectory"]): raise FtpServerException("Directory for logs does not exists !")
        # We must have access to logdirectory
        if not self._write_read_able(self.config["logdirectory"]): raise FtpServerException("Logs directory is not writeable/readable")
        # Check if we can found file with user accounts
        if not os.path.isfile(self.config["usernamefile"]) or not os.path.exists(self.config["usernamefile"]): raise FtpServerException("Username file does not exists !")
        # Load user accounts info (pairs login->password)
        try:
            num_row = 1
            with open(self.config["usernamefile"]) as f_acc:
                for rec in f_acc:
                    login, password = rec.split()
                    self.accounts[login.strip()] = password.strip()
                    num_row += 1
        except(IOError):
            raise FtpServerException("Cannot open/read accounts file: %s" % (self.config["usernamefile"]))
        except(ValueError):
            raise FtpServerException("Accounts file bad format.\nExpected pairs: <login> <password>.\nError occured at line=%d" % (num_row))
        # List of connected clients
        self.clients = []
        self.running = False
        # Validate argumens
        # log_file_name should be valid filename, 
        # port should be a positive integer
        try:
            # Parse remote port
            self.port = int(server_port)
            if(self.port <= 0):
                raise ValueError
            # Finally work with log file
            logdir = self.config["logdirectory"]
            # If we must care about logfiles
            if self.config.get("numlogfiles", None) != None:
                max_logs_num = int(self.config["numlogfiles"])
                if max_logs_num < 1: raise FtpServerException("Numlogfiles value error")
                # Check if logfile with this name already exists
                if os.path.exists(os.path.join(logdir, log_file_name)) and os.path.isfile(os.path.join(logdir, log_file_name)):
                    # if file exists with this name then we must decide how to rename previus file
                    # for this lets get list of all files from this directory 
                    # but filter to grab only filename that start with current log_file_name
                    logfiles = [f for f in os.listdir(logdir) if os.path.isfile(os.path.join(logdir, f)) and f.startswith(log_file_name)]
                    # Calculate length of filename + 1
                    n = len(log_file_name + ".")
                    # Filter file endings (numbers 001, 002, 003 ... etc)
                    temp = [f[n:] for f in logfiles if f[n:].isdigit() ]
                    # Find max file number 
                    maxnumber = -1
                    for t in temp:
                        if int(t) > maxnumber: maxnumber = int(t)
                    # Update maxnumber for use for next fime
                    maxnumber = maxnumber + 1
                    # If we still within the range of max_logs_num
                    if maxnumber < max_logs_num:
                        # Rename old filename (just append "." + logfile number)
                        os.rename(os.path.join(logdir, log_file_name), os.path.join(logdir, log_file_name + "." + str(maxnumber).zfill(3) ))
                        # And open new file
                        self.f = open(os.path.join(logdir, log_file_name), "a+")
                    else:
                        # rename old files and remove oldest
                        try:
                            # Remove oldest log file (file with "000" prefix)
                            oldest = os.path.join(logdir, log_file_name + ".000")
                            if os.path.exists(oldest) and os.path.isfile(oldest):
                                os.remove(oldest)
                            # Next part is rename all files that have same log_file_name but ending different
                            # Example: if we want to store max 5 last log files
                            # We can create new files untill their ending number reached "004"
                            # after that we must remove oldest (witch always "000")
                            # iterate throught files and rename ending number or simpli decrease this number
                            # lets say we have in logs folder next files: 
                            # logfile.000
                            # logfile.001
                            # logfile.002
                            # logfile.003
                            # logfile.004
                            # first we remove "logfile.000" and then perform remove operations:
                            # logfile.001 -> become logfile.000
                            # logfile.002 -> logfile.001
                            # logfile.003 -> logfile.002
                            # logfile.004 -> logfile.003
                            # And now we have an empty space for new file
                            for num in range(0, maxnumber - 1):
                                # Constuct string with old filename
                                oldname = os.path.join(logdir, log_file_name + "." + str(num + 1).zfill(3))
                                # Check if this file exists if not -> just go to the file with next number
                                if not os.path.exists(oldname) or not os.path.isfile(oldname): continue
                                # Otherwise constuct new filename
                                newname = os.path.join(logdir, log_file_name + "." + str(num).zfill(3))
                                # and rename old file
                                os.rename(oldname, newname)
                        except Exception as e:
                            raise FtpServerException("Unable to clear old log files !: " + str(e))
                        # Finaly open the log file
                        self.f = open(os.path.join(logdir, log_file_name), "a+")
                # File not found or doesnt exists
                else:# open new log file with append mode
                    self.f = open(os.path.join(logdir, log_file_name), "a+")
            else: # Otherwise just open new or old with append mode
                # open log file with append mode
                self.f = open(os.path.join(logdir, log_file_name), "a+")
        except(IOError):
            raise FtpServerException("Cannot open/create log file")
        except(ValueError):
            raise FtpServerException("Server port should be a positive integer")
        # Write num of accounts loaded
        self.log("%d account records loaded." % len(self.accounts))
    ###############################################################
    # Check if directory readable/writeable
    def _write_read_able(self, dir):
        # Try to create empty temp file
        try:
            with open(os.path.join(dir, 'temp'), 'w') as tmp:
                pass
        # While creating error occured -> directory is not writeable
        except Exception as e:
            print(e)
            return False
        else: # Otherwise try to remove this temp file
            try:
                os.remove(os.path.join(dir, 'temp'))
            except Exception as e: # Unable to remove ? -> not readable ?
                print(e)
                return False
            return True
    ###############################################################
    # Override __enter__ method with allow us to use object of our class in "with" statements (automaticly close resource: sockets, files)
    def __enter__(self):
        return self
    ###############################################################
    # This will be called after leave "with" statement
    def __exit__(self, exc_type, exc_value, traceback):
        # Close listen socket and disconnect all clients
        self.stopServer()
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
    def startServer(self):
        if self.running: return
        self.log("Starting server on port %d...." % self.port)
        try:
            # Listn socket to accept incoming clients
            self.serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #self.serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.serv_sock.setblocking(0)
            self.serv_sock.settimeout(2)
            # Bind to all interfaces but on specifed port
            self.serv_sock.bind(("0.0.0.0", self.port))
            # Start listen
            self.serv_sock.listen(0)
        except socket.error, (errorCode, message):
            self.running = False
            if errorCode == 10048: self.log("Server start FAIL: \"address already in use\"")
            else: self.log("Server start FAIL: %s" %(message))
            serverStartEvent.set()
            serverStopEvent.set()
            return
        self.running = True
        self.log("Server start OK.")
        self.log("Server running on port %d. Waiting for clients..." % self.port)
        serverStartEvent.set()
        try:
            # Accept loop 
            while self.running:
                _in, out, _exc = select.select([self.serv_sock,], [], [], 1)
                for s in _in:
                    if s != self.serv_sock: continue
                    client = Client(self.serv_sock.accept(), self.log, self.accounts, self.config)
                    self.log( "Client from %s %d" % client.addr + " accepted" )
                    # Add new client to list
                    self.clients.append(client)
                    # Handle client
                    client.start()
        except Exception as e:
            self.log("Error while acception loop: " + str(e))
        # If we reach this line then server should be onStop event
        # Stop listen socket
        self.serv_sock.close()        
        self.stopServer()
    ###############################################################
	# Stop sever, close all client connections, cleanup sockets
    def stopServer(self):
        if not self.running: return
        self.log("Stopping server...")
        # Mark running status to false
        self.running = False
        try:
            # Close client connections
            for c in self.clients:
                c.close_connection()        
                c.join()
            # Close file
            self.f.close()
            self.log("All clients disconnected. Server succefuly stoped.")
        except:
            pass
        serverStopEvent.set()
    ###############################################################
    # Return string of current time stamp
    def get_timestamp(self):
        # Get current date/time and convert to string using specified format
        return datetime.datetime.now().strftime('%m/%d/%Y %H:%M:%S.%f')
    ###############################################################
    # Log message to console and logfile
    def log(self, message):
        # Block current thread until it can obtail lock
        lock.acquire()
        # Get timestamp
        ts = self.get_timestamp()
        # Print to console
        print( ts + " " + message )
        # Append to lof file
        self.f.write(ts + " " + message + "\n")
        # Release block
        lock.release()        
###############################################################
# Main function
def main():
    # Receive command line arguments
    args = sys.argv[1:]
    # 2 arguments required [logfile, port]
    if(len(args) != 2):
        print_usage()
        return None
    # Get command line arguments
    log_file_name, port = args[0], args[1]
    try:
        # Create ftp server object
        ftp = FtpServer(log_file_name, port)
        # Create server thread
        th = threading.Thread(target=ftp.startServer)
        # Run server thread
        th.start()
        # Wait while serverStartEvent will be maked
        serverStartEvent.wait()
        # Commands to server (only one -> stop)
        while not serverStopEvent.wait(0):
            cmd = raw_input(">")
            if str.lower(cmd) == "stop": break
            # We can add commands like to live interact with server (add/edit user, or maybe list all clients, disconnect, etc, up 2 u)
        serverStopEvent.set()
        ftp.stopServer()
        th.join()
        print("Server thread stop.")
    except FtpServerException as e:
        print(e)
###############################################################
# if we use this not as module -> just run main function
if __name__ == "__main__":
	main()
###############################################################