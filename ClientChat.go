package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"strconv"
	"strings"
	"time"
)

type Crypto struct {
	public_key_pem string
	private_key    *rsa.PrivateKey
	public_key     rsa.PublicKey
}

type Cert struct {
	certPem []byte
	keyPem  []byte
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

type pmCrypto struct {
	publicKey     *rsa.PublicKey
	chatKey       []byte
	chatKeyHashed [32]byte
	iv            []byte
	aesBlock      cipher.Block
	nyapaAntiBug  string
}

func main() {

	var text string
	var err error

	var crypto Crypto     //Data about private/public key of the client
	var pmCrypto pmCrypto //Data about keys of the private message
	pmCrypto.nyapaAntiBug = "shutup"

	host := "127.0.0.1"
	port := "9988"

	reader := bufio.NewReader(os.Stdin)


	//log.SetOutput(ioutil.Discard)

	CreateLogFile()

	/**********************************************************/
	/************* Config cert and tls connection *************/
	/**********************************************************/
	cryptoCert := generatePrivateKey()
	certPem := generateCert(cryptoCert.private_key)

	cert, err := tls.X509KeyPair(certPem.certPem, certPem.keyPem)

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	fmt.Println("Connecting to server (", host, ":", port, ")")
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8000", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	log.Println("client: connected to: ", conn.RemoteAddr())
	/**********************************************************/

	if err != nil {
		fmt.Println("#ERROR trying connect with server (", conn.RemoteAddr(), ")")
	} else {

		crypto = generatePrivateKey()

		go readJSONCommandFromServer(conn, &pmCrypto, crypto)

		//Send to server, Name and public key
		initializationCommand := GenerateInitilizationCommand(crypto)
		writeJSONCommand(conn, initializationCommand)

		for err == nil {
			fmt.Print("#Say: ")

			//Read from keyboard
			text, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("#ERROR Reading from os.Stdin")
				fmt.Println("#ERROR description: ", err.Error())
			} else {

				text = strings.TrimSpace(text)

				command := stringToCommand(text, &pmCrypto)

				//commandString := CommandToJSONString(command)

				writeJSONCommand(conn, command)
			}

		}
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

func GenerateInitilizationCommand(crypto Crypto) Command {

	var command Command
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Choose a nickname: ")

	//Read from keyboard
	nickname, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("#ERROR Reading from os.Stdin")
		fmt.Println("#ERROR description: ", err.Error())
	} else {

		nickname = strings.TrimSpace(nickname)

		command = Command{Command: "initializeClient", Arg1: nickname, Arg2: crypto.public_key_pem}

	}

	return command
}

func readJSONCommandFromServer(conn net.Conn, pmCrypto *pmCrypto, crypto Crypto) {
	var command Command
	var err error = nil

	for err == nil {
		command, err = readJSONCommand(conn)
		if err == nil {

			switch command.Command {

			case "say":
				{
					if command.Arg1 != "" {
						fmt.Println("[", command.Sender, "]:", command.Arg1)
					}
					if len(command.Buffer) > 0 {
						plainText := decrypt(pmCrypto.aesBlock, command.Buffer, pmCrypto.iv)
						plainTextString := string(plainText[:len(plainText)])
						fmt.Println("[", command.Sender, "]:", plainTextString)
					}
				}
			case "list":
				{
					fmt.Println("[", command.Sender, "]:", command.Arg1)

					var userList []string

					_ = json.Unmarshal(command.Buffer, &userList)

					for _, v := range userList {

						fmt.Print("Nick: ")
						fmt.Println(v)
					}
				}

			case "publicKey":
				{
					//DEBUG
					//fmt.Println("#DEBUG: /publicKey")
					publicKeyPemString := command.Arg1

					publicKeyPem := []byte(publicKeyPemString)

					publicKeyBlock, _ := pem.Decode(publicKeyPem)

					publikKeyDER := publicKeyBlock.Bytes

					publicKey, _ := x509.ParsePKIXPublicKey(publikKeyDER)

					//Almacenamos la clave publica del objetivo
					pmCrypto.publicKey, _ = publicKey.(*rsa.PublicKey)
				}

			case "pmInitializeChatKey": //
				{
					
					b := make([]byte, 45)
					_, err := rand.Read(b)

					var initialKeyString string

					for _, value := range b {
						initialKeyString += strconv.Itoa(int(value))
					}

					initialKey := []byte(initialKeyString)

					/*
					 Function: EncryptPKCS1v15
					 The message must be no longer than the length of the public modulus minus 11 bytes.
					 WARNING: use of this function to encrypt plaintexts other than session keys is dangerous.
					 Use RSA OAEP in new protocols
					*/

					initialKeyEncrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pmCrypto.publicKey, initialKey)
					if err != nil {
						fmt.Println("#ERROR at /pmInitializeChatKey rsa.EncryptPKCS1v15(rand.Reader, pub, msg)")
					}
					//Datos encrip
					//initialKeyEncryptedString := string(initialKeyEncrypted[:len(initialKeyEncrypted)])

					//DEBUG
					/*fmt.Println("#DEBUG - initialKeyString: " + initialKeyString)
					fmt.Println("#DEBUG - initialKeyBytes: %p ", initialKey)
					fmt.Println("#DEBUG - initialKeyEncrypted: %p", initialKeyEncrypted)
					fmt.Println("#DEBUG - initialKeyEncryptedString: " + initialKeyEncryptedString)
					fmt.Println("#DEBUG - initialKeyEncryptedStrin Bytes Size: ", len(initialKeyEncrypted))*/

					//commandToSendString := newCommandString("pmInitializedChatKey", "", initialKeyEncryptedString, "", "", "", "")
					command := newCommandWithBuffer("pmInitializedChatKey", "", initialKeyEncrypted, "", "", "", "", "")
					writeJSONCommand(conn, command)

				}

		
			case "pmFinishChatKey":
				{
					initialKeyEncrypted := command.Buffer

					/*
						Function: DecryptPKCS1v15
						DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
					*/

					//Desencriptamos la clave parcial recibida con nuestra clave privada
					initialKey, err := rsa.DecryptPKCS1v15(rand.Reader, crypto.private_key, initialKeyEncrypted)

					if err != nil {
						fmt.Println("#ERROR at /pmFinishChatKey rsa.DecryptPKCS1v15(rand.Reader, priv, cypherMsg)")
						fmt.Println("#ERROR" + err.Error())
					} else {
						//fmt.Println("/pmFinishChatKey initialKey = " + string(initialKey))

						
						initialKeyString := string(initialKey[:len(initialKey)])
						b := make([]byte, 45)
						_, err := rand.Read(b)
						for _, value := range b {
							initialKeyString += strconv.Itoa(int(value))
						}

						pmFullChatKey := []byte(initialKeyString)

						pmCrypto.chatKey = pmFullChatKey
						/*pmCrypto = */ initializeAesCTR(pmCrypto)

						pmFullChatKeyEncrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pmCrypto.publicKey, pmFullChatKey)
						if err != nil {
							fmt.Println("#ERROR at /pmInitializeChatKey rsa.EncryptPKCS1v15(rand.Reader, pub, msg)")
							fmt.Println("#ERROR" + err.Error())
						} else {

							//pmFullChatKeyEncryptedString := string(pmFullChatKeyEncrypted[:len(pmFullChatKeyEncrypted)])
							//commandToSendString := newCommandString("pmCompleteChatKey", "", pmFullChatKeyEncryptedString, "", "", "", "")
							command := newCommandWithBuffer("pmCompleteChatKey", "", pmFullChatKeyEncrypted, "", "", "", "", "")
							writeJSONCommand(conn, command)
						}
					}

				}
			case "pmCompleteChatKey":
				{
					completeChatKeyEncrypted := command.Buffer

					completeChatKey, err := rsa.DecryptPKCS1v15(rand.Reader, crypto.private_key, completeChatKeyEncrypted)
					if err != nil {
						fmt.Println("#ERROR at /pmFinishChatKey rsa.ecryptPKCS1v15(rand.Reader, priv, cypherMsg)")
					} else {

						pmCrypto.chatKey = completeChatKey

						initializeAesCTR(pmCrypto)

					}
				}
			}
		}
	}

	if err != nil {
		fmt.Println("#ERROR recieving #MESSAGE from server (", conn.RemoteAddr(), ")")
		fmt.Println("#ERROR description: ", err.Error())
	}
}

func generatePrivateKey() Crypto {
	//Based on: https://github.com/golang-samples/cipher/blob/master/crypto/rsa_keypair.go

	// priv *rsa.PrivateKey;
	// err error;
	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		fmt.Println(err)
		panic("Error rsa.GenerateKey(rand.Reader, 2014)")
	}
	err = priv.Validate()
	if err != nil {
		fmt.Println("Validation failed.", err)
	}

	//Other private keys format
	/*
		// Get der format. priv_der []byte
		priv_der := x509.MarshalPKCS1PrivateKey(priv)

		// pem.Block
		// blk pem.Block
		priv_blk := pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   priv_der,
		}

		// Resultant private key in PEM format.
		 priv_pem string
		priv_pem := string(pem.EncodeToMemory(&priv_blk))
	*/
	//fmt.Printf(priv_pem)

	// Public Key generation
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

	crypto := Crypto{public_key_pem: pub_pem, private_key: priv, public_key: pub}

	return crypto
}

func stringToCommand(text string, pmCrypto *pmCrypto) Command {

	var command Command

	splitedMessage := strings.Fields(text)

	commandString := splitedMessage[0]
	firstChar := commandString[0]

	if firstChar == '/' {
	
		switch commandString {
		//Format: sender /pm reciever text
		case "/pm":
			{
				recieverName := splitedMessage[1]

				command = Command{Command: "pm", Arg1: recieverName}

				pmCrypto.nyapaAntiBug = "talk"
			}
		case "/list":
			{
				command = Command{Command: "list"}
			}
		case "/leave":
			{
				command = Command{Command: "leave"}

				pmCrypto.nyapaAntiBug = "shutup"
			}
		}
	} else {

		if pmCrypto.nyapaAntiBug == "talk" {
			cypheredText := encrypt(pmCrypto.aesBlock, []byte(text), pmCrypto.iv)
			command = newCommandWithBuffer("say", "", cypheredText, "", "", "", "", "")
		} else {
			fmt.Println("Use the command \"/pm user\" to initialize a chat witih \"user\"")
		}
	}

	return command
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

func newCommandString(command string, sender string, arg1 string, arg2 string, arg3 string, arg4 string, arg5 string) string {

	commandToSend := Command{
		Command: command,
		Sender:  sender,
		Arg1:    arg1,
		Arg2:    arg2,
		Arg3:    arg3,
		Arg4:    arg4,
		Arg5:    arg5,
	}
	commandToSendString := CommandToJSONString(commandToSend)

	return commandToSendString
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

	logName := "logs/" + timeString + ".Client.txt"

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

func CommandToJSONString(command Command) string {
	commandJSON, err := json.MarshalIndent(command, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}

	commandJSONString := string(commandJSON[:len(commandJSON)])

	return commandJSONString
}

//http://stackoverflow.com/questions/7263928/decrypt-using-the-ctr-mode
func generateIV(bytes int) []byte {
	/*
		b := make([]byte, bytes)
		rand.Read(b)
		return b
	*/
	var b []byte
	var i int
	for i = 0; i < bytes; i++ {
		b = append(b, 0)
	}

	return b
}

//http://stackoverflow.com/questions/7263928/decrypt-using-the-ctr-mode
func encrypt(block cipher.Block, value []byte, iv []byte) []byte {

	//fmt.Println("block size: ", block)
	//fmt.Println("block size: ", block.BlockSize())
	//fmt.Println("iv: " + string(iv[:len(iv)]))

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(value))
	stream.XORKeyStream(ciphertext, value)
	return ciphertext
}

//http://stackoverflow.com/questions/7263928/decrypt-using-the-ctr-mode
func decrypt(block cipher.Block, ciphertext []byte, iv []byte) []byte {
	stream := cipher.NewCTR(block, iv)
	plain := make([]byte, len(ciphertext))
	// XORKeyStream is used to decrypt too!
	stream.XORKeyStream(plain, ciphertext)
	return plain
}

//http://stackoverflow.com/questions/7263928/decrypt-using-the-ctr-mode
func initializeAesCTR(crypto *pmCrypto) /*pmCrypto*/ {

	crypto.chatKeyHashed = sha256.Sum256(crypto.chatKey)

	//var chatKeyHashedSlice []byte
	//chatKeyHashedSlice = crypto.chatKeyHashed[:]

	block, err := aes.NewCipher(crypto.chatKeyHashed[:])
	if err != nil {
		panic(err)
	}

	iv := generateIV(block.BlockSize())
	//value := "foobarbaz"
	//encrypted := encrypt(block, []byte(value), iv)
	//decrypted := decrypt(block, encrypted, iv)
	//fmt.Printf("--- %s ---", string(decrypted))

	crypto.aesBlock = block
	crypto.iv = iv

	//return crypto
}

/********************************************************************/
/************** GENERATE CERT AND PRIVATE KEY SECTION  **************/
/********************************************************************/

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
			Organization: []string{"SDS 2014 Co"},
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
