package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type Client struct {
	name               string
	public_key         string
	messageHandlerChan chan Command
	connection         net.Conn // interface connection (client)
	chatingWith        string   //Client.name o Channel.name
	//listenBuffer chan string // channels are the pipes that connect concurrent goroutines
	//writeBuffer  chan string // write buffer "messages <- 'Message Text' " read buffer "msg:= <- messages"
	//exit         chan bool   // listenBuffer, writeBuffer, exit, represents data between  goroutines
}

type Command struct {
	Sender  string
	Command string
	Buffer  []byte
	Arg1    string
	Arg2    string
	Arg3    string
	Arg4    string
	Arg5    string
}

type Crypto struct {
	public_key_pem  string
	private_key_pem string
	private_key     *rsa.PrivateKey
	public_key      rsa.PublicKey
}

type Cert struct {
	certPem []byte
	keyPem  []byte
}

type UserList struct {
	Users []string
}

func main() {

	crypto := generatePrivateKey()
	certPem := generateCert(crypto.private_key)

	cert, err := tls.X509KeyPair(certPem.certPem, certPem.keyPem)
	if err != nil {
		log.Fatalf("#ERROR server: loadkeys: %s", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
	config.Rand = rand.Reader
	service := "0.0.0.0:8000"

	CreateLogFile()

	clients := make(map[string]Client)

	messageHandlerChan := make(chan Command)

	go messageHandler(messageHandlerChan, clients)

	fmt.Println("Starting server...")

	netListen, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}

	fmt.Println("Accepting incoming clients...")

	for {
		conn, _ := netListen.Accept()
		clientHandler(conn, messageHandlerChan, clients)
	}

}

func read(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	return line, err
}

func write(conn net.Conn, data string) {

	writer := bufio.NewWriter(conn)
	writer.WriteString(data + "\n")
	writer.Flush()
}

func readJSONCommand(conn net.Conn) (Command, error) {

	var command Command

	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&command)

	logJSON("readJSONCommand(): ", command)

	return command, err
}

func writeJSONCommand(conn net.Conn, command Command) error {

	logJSON("writeJSONCommand(): ", command)

	encoder := json.NewEncoder(conn)
	err := encoder.Encode(&command)

	return err
}

func clientRecieve(client Client) {

	var err error = nil

	for err == nil {
		command, err := readJSONCommand(client.connection)
		if err == nil {

			command.Sender = client.name

			client.messageHandlerChan <- command

		}
	}

	if err != nil {
		fmt.Println("#ERROR recieving #MESSAGE from client: ", string(client.name), "(", client.connection.RemoteAddr(), ")")
		fmt.Println("#ERROR description: ", err.Error())
	}
}

func clientHandler(conn net.Conn, messageHandlerChan chan Command, clients map[string]Client) {
	command, err := readJSONCommand(conn)
	if err != nil {
		fmt.Println("#ERROR recieving #NAME from client adress: (", conn.RemoteAddr(), ")")
		fmt.Println("#ERROR description: ", err.Error())
	} else {

		//name - listenBuffer - writeBuffer - exit - connection
		newClient := Client{
			name:               command.Arg1,
			public_key:         command.Arg2,
			messageHandlerChan: messageHandlerChan,
			connection:         conn,
			chatingWith:        "",
		}

		fmt.Println("#Connected: ", newClient.name, " from (", conn.RemoteAddr(), ")")
		clients[newClient.name] = newClient
		go clientRecieve(newClient)
	}
}

func Append(slice, data []byte) []byte {
	l := len(slice)
	if l+len(data) > cap(slice) { // reallocate
		// Allocate double what's needed, for future growth.
		newSlice := make([]byte, (l+len(data))*2)
		// The copy function is predeclared and works for any slice type.
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0 : l+len(data)]
	for i, c := range data {
		slice[l+i] = c
	}
	return slice
}

func messageHandler(messageHandlerChan <-chan Command, clients map[string]Client) {

	var command Command

	for {

		command = <-messageHandlerChan

		switch command.Command {
		case "pm":
			{
				pmFrom := command.Sender
				pmTo := command.Arg1

				sender := clients[pmFrom]
				reciever := clients[pmTo]

				if reciever.chatingWith != "" {

					textToSay := reciever.name + " busy"
					command = newCommand("say", "Server", textToSay, "", "", "", "")
					writeJSONCommand(sender.connection, command)

				} else if sender.name == reciever.name {

					textToSay := "You can not create chat with yourself"
					command = newCommand("say", "Server", textToSay, "", "", "", "")
					writeJSONCommand(sender.connection, command)

				} else {

					sender.chatingWith = reciever.name
					reciever.chatingWith = sender.name

					clients[sender.name] = sender
					clients[reciever.name] = reciever

					command = newCommand("say", "Server", "#PM Private chat between "+sender.name+" y "+reciever.name, "", "", "", "")
					writeJSONCommand(sender.connection, command)
					fmt.Println("#PM(", sender.name, ",", reciever.name, ")", sender.name, " /say")
					writeJSONCommand(reciever.connection, command)
					fmt.Println("#PM(", sender.name, ",", reciever.name, ")", reciever.name, " /say")

					command = newCommand("publicKey", sender.name, sender.public_key, "", "", "", "")
					writeJSONCommand(reciever.connection, command)
					fmt.Println("#PM(", sender.name, ",", reciever.name, ")", reciever.name, " /publicKey")

					command = newCommand("publicKey", reciever.name, reciever.public_key, "", "", "", "")
					writeJSONCommand(sender.connection, command)
					fmt.Println("#PM(", sender.name, ",", reciever.name, ")", sender.name, " /publicKey")

					command = newCommand("pmInitializeChatKey", "Server", "", "", "", "", "")
					writeJSONCommand(sender.connection, command)
					fmt.Println("#PM(", sender.name, ",", reciever.name, ")", sender.name, " /pmInitializeChatKey")

				}
			}

		case "list":
			{
				sender := clients[command.Sender]

				var userList []string

				for _, v := range clients {
					userList = append(userList, v.name)
				}

				userListBytes, _ := json.MarshalIndent(userList, "", "    ")

				command = newCommandWithBuffer("list", "Server", userListBytes, "Sending list...", "", "", "", "")
				writeJSONCommand(sender.connection, command)
			}

		case "leave":
			{
				sender := clients[command.Sender]

				if sender.chatingWith != "" {

					for _, v := range clients {

						if sender.chatingWith == v.name {

							sender.chatingWith = ""
							v.chatingWith = ""

							message1 := "User " + sender.name + " has leave the room"
							command = newCommand("list", "Server", message1, "", "", "", "")
							writeJSONCommand(v.connection, command)

							message2 := "You have leave the room with " + v.name
							command = newCommand("list", "Server", message2, "", "", "", "")
							writeJSONCommand(sender.connection, command)

							break
						}
					}
				} else {

					textToSay := "Your are not in a room"
					command = newCommand("say", "Server", textToSay, "", "", "", "")
					writeJSONCommand(sender.connection, command)
				}
			}

		case "say":
			{
				sender := clients[command.Sender]

				if sender.chatingWith == "" {

					command = newCommand("say", "Server", "Init chat with \"/pm UserName\"", "", "", "", "")
					writeJSONCommand(sender.connection, command)

				} else {

					recieverName := sender.chatingWith
					reciever := clients[recieverName]
					textToSay := command.Arg1
					CypheredText := command.Buffer
					command = newCommandWithBuffer("say", sender.name, CypheredText, textToSay, "", "", "", "")
					writeJSONCommand(reciever.connection, command)
				}

			}
		case "pmInitializedChatKey":
			{ 
				sender := clients[command.Sender]
				recieverName := sender.chatingWith
				reciever := clients[recieverName]

				initialEncryptedKey := command.Buffer

				command = newCommandWithBuffer("pmFinishChatKey", "Server", initialEncryptedKey, "", "", "", "", "")
				writeJSONCommand(reciever.connection, command)
				fmt.Println("#PM(", sender.name, ",", reciever.name, ")", reciever.name, " /pmFinishChatKey")

			}
		case "pmCompleteChatKey":
			{
				sender := clients[command.Sender]
				recieverName := sender.chatingWith
				reciever := clients[recieverName]

				completeChatKeyEncrypted := command.Buffer

				command = newCommandWithBuffer("pmCompleteChatKey", "Server", completeChatKeyEncrypted, "", "", "", "", "")
				writeJSONCommand(reciever.connection, command)
				fmt.Println("#PM(", sender.name, ",", reciever.name, ")", reciever.name, " /pmCompleteChatKey")

			}
		}

	}
}

func JSONStringToCommand(commandJSONString string) Command {

	var command Command

	commandJSON := []byte(commandJSONString)
	err := json.Unmarshal(commandJSON, &command)
	if err != nil {
		fmt.Println("error:", err)
	}

	return command
}

func CommandToJSONString(command Command) string {
	commandJSON, err := json.MarshalIndent(command, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}

	commandJSONString := string(commandJSON[:len(commandJSON)])

	return commandJSONString
}

func newCommand(command string, sender string, arg1 string, arg2 string, arg3 string, arg4 string, arg5 string) Command {

	newCommand := Command{
		Command: command,
		Sender:  sender,
		Arg1:    arg1,
		Arg2:    arg2,
		Arg3:    arg3,
		Arg4:    arg4,
		Arg5:    arg5,
	}

	return newCommand
}

func newCommandWithBuffer(command string, sender string, buffer []byte, arg1 string, arg2 string, arg3 string, arg4 string, arg5 string) Command {

	newCommand := Command{
		Command: command,
		Sender:  sender,
		Buffer:  buffer,
		Arg1:    arg1,
		Arg2:    arg2,
		Arg3:    arg3,
		Arg4:    arg4,
		Arg5:    arg5,
	}

	return newCommand
}

//func CreateLogFile() *log.Logger {
func CreateLogFile() {

	// open output file
	t := time.Now().Local()
	timeString := t.Format("2006-01-02_15:04:05")

	logName := "logs/" + timeString + ".Server.txt"

	fo, err := os.Create(logName)
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	//w := bufio.NewWriter(fo)

	//logger := log.New(w, "LOG: ", log.Ldate|log.Ltime|log.Lshortfile)

	log.SetOutput(fo)

	fmt.Println("Logging at: " + logName)

	//return logger
}

func logJSON(location string, command Command) {

	commandString := CommandToJSONString(command)

	log.Println(location + commandString)
}

/********************************************************************/
/************** GENERATE CERT AND PRIVATE KEY SECTION  **************/
/********************************************************************/

func generatePrivateKey() Crypto {

	//PrivateKey section

	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		fmt.Println(err)
		panic("Error rsa.GenerateKey(rand.Reader, 2014)")
	}

	generateCert(priv)

	err = priv.Validate()
	if err != nil {
		fmt.Println("Validation failed.", err)
	}

	//DER (Distinguish Encoding Rules)
	priv_der := x509.MarshalPKCS1PrivateKey(priv) //PKCS1 (RSA) - Private-Key

	priv_blk := pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   priv_der,
	}

	//PEM (Privacy Enhanced Mail).
	priv_pem := string(pem.EncodeToMemory(&priv_blk))

	//PublicKey section

	pub := priv.PublicKey

	pub_der, err := x509.MarshalPKIXPublicKey(&pub) //PKIX - Public-Key Infrastructure
	if err != nil {
		fmt.Println("Failed to get der format for PublicKey.", err)
		panic("Error x509.MarshalPKIXPublicKey(&pub)")
	}

	pub_blk := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pub_der,
	}

	pub_pem := string(pem.EncodeToMemory(&pub_blk))

	crypto := Crypto{public_key_pem: pub_pem, private_key_pem: priv_pem, private_key: priv, public_key: pub}

	return crypto
}

func generateCert(priv *rsa.PrivateKey) Cert {

	host, err := os.Hostname()
	if err != nil {
		log.Fatalf("#ERROR: failed to get HostName: %s", err)
		panic("")
	}

	//Start date
	//var notBefore time.Time
	notBefore := time.Now()
	//Duration
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// end of ASN.1 time
	endOfTime := time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	if notAfter.After(endOfTime) {
		notAfter = endOfTime
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			Organization: []string{"SDS 2014"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var isCA = false

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		panic("")
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return Cert{certPem: certPem, keyPem: keyPem}
}
