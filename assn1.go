package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User : The structure definition for a user record
type User struct {
	Username             string
	RSAPrivateKey        userlib.PrivateKey
	MasterIndexNodeTuple Tuple
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// Tuple : The tuple defined in the design document
type Tuple struct {
	Location []byte
	AESKey   []byte
	HMACKey  []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// InitUser : You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Generate RSA keys and store the public key
	rsaPtr, err := userlib.GenerateRSAKey()
	if err != nil {
		err := errors.New("could not create RSA keys")
		userlib.DebugMsg("InitUser: %v", err)
		return nil, err
	}
	userlib.KeystoreSet(username, rsaPtr.PublicKey)

	// Generate and store the master index node
	masterIndexNodeTuple := generateTuple()
	initMasterIndexNode(masterIndexNodeTuple)

	// Generate user struct
	var userdata User

	userdata.Username = username
	userdata.RSAPrivateKey = *rsaPtr
	userdata.MasterIndexNodeTuple = masterIndexNodeTuple

	// Encode user struct as JSON
	userdataJSON, err := json.Marshal(userdata)
	if err != nil {
		err := errors.New("could not marshal userdata to JSON")
		userlib.DebugMsg("InitUser: %v", err)
		return nil, err
	}

	// Generate user struct Tuple and store user struct
	r1, r2, userStructTuple := genUserStructSaltsAndTuple(username, password)
	storeUserStruct(r1, r2, userStructTuple, userdataJSON)

	return &userdata, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	/* Constants start */
	r1Length := userlib.AESKeySize
	r2Length := userlib.HashSize
	ivLength := userlib.BlockSize
	tagLength := userlib.HashSize
	minUserStructLength := r1Length + r2Length + ivLength + 1 + tagLength
	// r1 || r2 || iv || ciphertext || tag
	// +1 since ciphertext should not be empty

	// Slice indices
	r1Start := 0
	r1End := r1Start + r1Length
	r2Start := r1End
	r2End := r2Start + r2Length
	ivStart := r2End
	ivEnd := ivStart + ivLength
	cipherTextStart := ivEnd

	// Generic error message
	genericError := errors.New("Error getting user")
	/* Constants end */

	// Calculate user struct location and value at that location
	location := getUserStructLocation(username, password)
	locStr := hex.EncodeToString(location)
	value, ok := userlib.DatastoreGet(locStr)
	if !ok {
		userlib.DebugMsg("GetUser: user struct does not exist at location: %v", locStr)
		return nil, genericError
	}

	// Check it has at least minimum length
	valueLength := len(value)
	if valueLength < minUserStructLength {
		userlib.DebugMsg("GetUser: value less than min length: %v", valueLength)
		return nil, genericError
	}

	tagStart := valueLength - tagLength
	tagEnd := valueLength
	cipherTextEnd := tagStart

	// Get the salts, iv, ciphertext and the tag
	r1 := value[r1Start:r1End]
	r2 := value[r2Start:r2End]
	iv := value[ivStart:ivEnd]
	cipherText := value[cipherTextStart:cipherTextEnd]
	tag := value[tagStart:tagEnd]

	aesKey, hmacKey := getUserAESAndHMACKeys(r1, r2, username, password)

	if !validMAC(location, value[:tagStart], tag, hmacKey) {
		userlib.DebugMsg("GetUser: invalid hmac tag, location: %v", locStr)
		return nil, genericError
	}

	decStream := userlib.CFBDecrypter(aesKey, iv)
	decStream.XORKeyStream(cipherText, cipherText)
	plainText := cipherText

	var userdata User

	if err := json.Unmarshal(plainText, &userdata); err != nil {
		userlib.DebugMsg("GetUser: failed to unmarshal: %v", err)
		return nil, genericError
	}

	return &userdata, nil
}

// StoreFile : This stores a file in the datastore.
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	masterIndexNode := userdata.loadMasterIndexNode()

	indexNodeTuple, ok := masterIndexNode[filename]
	if !ok {
		// File doesn't exist
		indexNodeTuple = generateTuple()
		masterIndexNode[filename] = indexNodeTuple
		userdata.updateMasterIndexNode(masterIndexNode)
	}

	newIndexNode := make(map[int]Tuple)

	newBlockTuple := generateTuple()
	newIndexNode[0] = newBlockTuple

	newIndexNodeJSON, err := json.Marshal(newIndexNode)
	if err != nil {
		userlib.DebugMsg("StoreFile: failed to Marshal: %v", err)
		panic(err)
	}

	storeUsingTuple(newBlockTuple, data)
	storeUsingTuple(indexNodeTuple, newIndexNodeJSON)
}

// AppendFile : This adds on to an existing file.
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	masterIndexNode := userdata.loadMasterIndexNode()

	indexNodeTuple, ok := masterIndexNode[filename]
	if !ok {
		userlib.DebugMsg("AppendFile: file does not exist, masterIndexNode: %v", masterIndexNode)
		return errors.New("file does not exist")
	}

	var indexNode map[int]Tuple

	value, err := loadUsingTuple(indexNodeTuple)
	if err != nil {
		userdata.deleteFile(masterIndexNode, filename)
		userlib.DebugMsg("AppendFile: file is corrupted, masterIndexNode: %v", masterIndexNode)
		return errors.New("file is corrupted. deleted entry for file")
	}

	if err := json.Unmarshal(value, &indexNode); err != nil {
		userlib.DebugMsg("AppendFile: failed to Unmarshal: %v", err)
		panic(err)
	}

	// Generate a new tuple for the new block and store it in the index node
	indexNodeLength := len(indexNode)
	newBlockTuple := generateTuple()
	indexNode[indexNodeLength] = newBlockTuple

	// Store the new block and update the index node
	indexNodeJSON, err := json.Marshal(indexNode)
	if err != nil {
		userlib.DebugMsg("AppendFile: failed to Marshal: %v", err)
		panic(err)
	}

	storeUsingTuple(newBlockTuple, data)
	storeUsingTuple(indexNodeTuple, indexNodeJSON)

	return nil
}

// LoadFile : This loads a file from the Datastore.
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileCorruptedError := errors.New("file is corrupted. deleted entry for file")

	masterIndexNode := userdata.loadMasterIndexNode()

	indexNodeTuple, ok := masterIndexNode[filename]
	if !ok {
		userlib.DebugMsg("LoadFile: file does not exist, masterIndexNode: %v", masterIndexNode)
		return nil, errors.New("file does not exist")
	}

	var indexNode map[int]Tuple

	value, err := loadUsingTuple(indexNodeTuple)
	if err != nil {
		userdata.deleteFile(masterIndexNode, filename)
		userlib.DebugMsg("LoadFile: loadUsingTuple failed, err: %v", err)
		return nil, fileCorruptedError
	}

	if err := json.Unmarshal(value, &indexNode); err != nil {
		userlib.DebugMsg("LoadFile: failed to Unmarshal: %v", err)
		panic(err)
	}

	var fileContents []byte

	numBlocks := len(indexNode)

	for i := 0; i < numBlocks; i++ {
		blockTuple, ok := indexNode[i]
		if !ok {
			userdata.deleteFile(masterIndexNode, filename)
			userlib.DebugMsg("LoadFile: no tuple for block, indexNode: %v", indexNode)
			return nil, fileCorruptedError
		}

		value, err := loadUsingTuple(blockTuple)
		if err != nil {
			userdata.deleteFile(masterIndexNode, filename)
			userlib.DebugMsg("LoadFile: loading block failed, blockTuple: %v", blockTuple)
			return nil, fileCorruptedError
		}

		fileContents = append(fileContents, value...)
	}

	return fileContents, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	CipherText []byte
	Signature  []byte
}

// ShareFile : This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.
// This enables the recipient to access the encrypted file as well
// for reading/appending.
// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	masterIndexNode := userdata.loadMasterIndexNode()

	// Check if file exists
	indexNodeTuple, ok := masterIndexNode[filename]
	if !ok {
		userlib.DebugMsg("ShareFile: file does not exist, masterIndexNode: %v", masterIndexNode)
		return "", errors.New("file does not exist")
	}

	// Convert the tuple to json for sharing
	plainText, err := json.Marshal(indexNodeTuple)
	if err != nil {
		userlib.DebugMsg("ShareFile: failed to Marshal: %v", err)
		panic(err)
	}

	// Get RSA public key of the recipient
	pubKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		userlib.DebugMsg("ShareFile: recipient does not exist, recipient: %v", recipient)
		return "", errors.New("recipient does not exist")
	}

	// Encrypt the tuple using recipient's public key
	cipherText, err := userlib.RSAEncrypt(&pubKey, plainText, []byte("share"))
	if err != nil {
		userlib.DebugMsg("ShareFile: RSAEncrypt failed, err: %v", err)
		return "", errors.New("failed to encrypt using recipient's public key")
	}

	// Sign the message with our private key
	signature, err := userlib.RSASign(&userdata.RSAPrivateKey, cipherText)
	if err != nil {
		userlib.DebugMsg("ShareFile: RSASign failed, err: %v", err)
		return "", errors.New("unable to sign the share message")
	}

	signedJSON, err := json.Marshal(sharingRecord{cipherText, signature})
	if err != nil {
		userlib.DebugMsg("ShareFile: failed to Marshal: %v", err)
		panic(err)
	}

	return hex.EncodeToString(signedJSON), nil
}

// ReceiveFile : Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	corruptedError := errors.New("share message is corrupted")
	userlib.DebugMsg("ReceiveFile: msgid: %v", msgid)

	signedJSON, err := hex.DecodeString(msgid)
	if err != nil {
		return corruptedError
	}

	var signed sharingRecord
	if err := json.Unmarshal(signedJSON, &signed); err != nil {
		userlib.DebugMsg("ReceiveFile: failed to Unmarshal signedJSON: %v", err)
		return corruptedError
	}

	pubKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		userlib.DebugMsg("ReceiveFile: no sender public key, sender: %v", sender)
		return errors.New("sender's public key does not exist in keystore")
	}

	if err := userlib.RSAVerify(&pubKey, signed.CipherText, signed.Signature); err != nil {
		userlib.DebugMsg("ReceiveFile: RSAVerify failed, err: %v", err)
		userlib.DebugMsg("cipherText: %v\nsignature: %v\n", signed.CipherText, signed.Signature)
		return errors.New("share message is not authentic")
	}

	plainText, err := userlib.RSADecrypt(&userdata.RSAPrivateKey, signed.CipherText, []byte("share"))
	if err != nil {
		userlib.DebugMsg("ReceiveFile: RSADecrypt failed, err: %v", err)
		return corruptedError
	}

	var indexNodeTuple Tuple
	if err := json.Unmarshal(plainText, &indexNodeTuple); err != nil || !validTuple(indexNodeTuple) {
		userlib.DebugMsg("ReceiveFile: failed to Unmarshal plainText: %v", err)
		return corruptedError
	}

	if _, err := loadUsingTuple(indexNodeTuple); err != nil {
		userlib.DebugMsg("ReceiveFile: shared file does not exist, indexNodeTuple: %v", indexNodeTuple)
		return errors.New("index node for shared file does not exist")
	}

	masterIndexNode := userdata.loadMasterIndexNode()
	masterIndexNode[filename] = indexNodeTuple
	userdata.updateMasterIndexNode(masterIndexNode)

	return nil
}

// RevokeFile : Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	masterIndexNode := userdata.loadMasterIndexNode()

	fileContents, err := userdata.LoadFile(filename)
	if err != nil {
		userlib.DebugMsg("RevokeFile: LoadFile failed, filename: %v, err: %v", filename, err)
		return err
	}

	userdata.deleteFile(masterIndexNode, filename)
	userdata.StoreFile(filename, fileContents)

	return nil
}

// Helper functions

// generateTuple: generate a normal tuple
func generateTuple() Tuple {
	var newTuple Tuple

	newTuple.Location = userlib.RandomBytes(userlib.AESKeySize)
	newTuple.AESKey = userlib.RandomBytes(userlib.AESKeySize)
	newTuple.HMACKey = userlib.RandomBytes(userlib.HashSize)

	return newTuple
}

func validTuple(t Tuple) bool {
	if len(t.Location) == userlib.AESKeySize && len(t.AESKey) == userlib.AESKeySize && len(t.HMACKey) == userlib.HashSize {
		return true
	}

	return false
}

// genUserStructTuple: generate the salts and tuple for a user struct
func genUserStructSaltsAndTuple(username string, password string) ([]byte, []byte, Tuple) {
	// Constants
	locSize := uint32(userlib.AESKeySize)
	aesSize := uint32(userlib.AESKeySize)
	hmacSize := uint32(userlib.HashSize)
	usrBytes := []byte(username)
	passBytes := []byte(password)

	// Generate random salts
	r1 := userlib.RandomBytes(userlib.AESKeySize)
	r2 := userlib.RandomBytes(userlib.HashSize)

	var userStructTuple Tuple

	userStructTuple.Location = userlib.Argon2Key(usrBytes, passBytes, locSize)
	userStructTuple.AESKey = userlib.Argon2Key(passBytes, r1, aesSize)
	userStructTuple.HMACKey = userlib.Argon2Key(passBytes, r2, hmacSize)

	return r1, r2, userStructTuple
}

func getUserStructLocation(username string, password string) []byte {
	return userlib.Argon2Key([]byte(username), []byte(password), uint32(userlib.AESKeySize))
}

func getUserAESAndHMACKeys(r1 []byte, r2 []byte, username string, password string) ([]byte, []byte) {
	aesKey := userlib.Argon2Key([]byte(password), r1, uint32(userlib.AESKeySize))
	hmacKey := userlib.Argon2Key([]byte(password), r2, uint32(userlib.HashSize))

	return aesKey, hmacKey
}

func storeUsingTuple(t Tuple, data []byte) {
	/* Constants start */
	ivLength := userlib.BlockSize
	ivCipherTextLength := ivLength + len(data)

	// Slice indices
	ivStart := 0
	ivEnd := ivStart + ivLength
	cipherTextStart := ivEnd
	/* Constants end */

	// AES Stuff
	iv := userlib.RandomBytes(ivLength)
	encStream := userlib.CFBEncrypter(t.AESKey, iv)

	// HMAC Stuff
	hmac := userlib.NewHMAC(t.HMACKey)

	// Encrypt
	ivCipherText := make([]byte, ivCipherTextLength)
	copy(ivCipherText[ivStart:ivEnd], iv)
	encStream.XORKeyStream(ivCipherText[cipherTextStart:], data)

	// Tag
	hmac.Write(t.Location)
	hmac.Write(ivCipherText)
	tagged := hmac.Sum(ivCipherText)

	// Store encrypted tagged data
	userlib.DatastoreSet(hex.EncodeToString(t.Location), tagged)
}

func loadUsingTuple(t Tuple) ([]byte, error) {
	if !validTuple(t) {
		userlib.DebugMsg("tuple invalid. tuple: %v", t)
		return nil, errors.New("not a valid tuple")
	}

	/* Constants start */
	ivLength := userlib.BlockSize
	tagLength := userlib.HashSize
	minValueLength := ivLength + tagLength
	// iv || ciphertext || tag
	// ciphertext could be empty

	// Slice indices
	ivStart := 0
	ivEnd := ivStart + ivLength
	cipherTextStart := ivEnd

	locStr := hex.EncodeToString(t.Location)
	/* Constants end */

	// Get the value at the location
	value, ok := userlib.DatastoreGet(locStr)
	if !ok {
		userlib.DebugMsg("no value at location: %v", locStr)
		return nil, errors.New("no value exists at location")
	}

	// Check that value has at least minimum length
	valueLength := len(value)
	if valueLength < minValueLength {
		userlib.DebugMsg("less than min length. length: %v, location: %v", valueLength, locStr)
		return nil, errors.New("value is less than minimum length")
	}

	tagStart := valueLength - tagLength
	tagEnd := valueLength
	cipherTextEnd := tagStart

	// Get the iv, ciphertext and the tag
	iv := value[ivStart:ivEnd]
	cipherText := value[cipherTextStart:cipherTextEnd]
	tag := value[tagStart:tagEnd]

	// Verify the tag
	if !validMAC(t.Location, value[:tagStart], tag, t.HMACKey) {
		userlib.DebugMsg("invalid hmac tag. location: %v", locStr)
		return nil, errors.New("hmac tag is not valid")
	}

	// Decrypt the value
	decStream := userlib.CFBDecrypter(t.AESKey, iv)
	decStream.XORKeyStream(cipherText, cipherText)
	plainText := cipherText

	return plainText, nil
}

func storeUserStruct(r1 []byte, r2 []byte, t Tuple, userdataJSON []byte) {
	/* Constants start */
	r1Length := userlib.AESKeySize
	r2Length := userlib.HashSize
	ivLength := userlib.BlockSize
	saltsIVCipherTextLength := r1Length + r2Length + ivLength + len(userdataJSON)

	// Slice indices
	r1Start := 0
	r1End := r1Start + r1Length
	r2Start := r1End
	r2End := r2Start + r2Length
	ivStart := r2End
	ivEnd := ivStart + ivLength
	cipherTextStart := ivEnd
	/* Constants end */

	// AES stuff
	iv := userlib.RandomBytes(ivLength)
	encStream := userlib.CFBEncrypter(t.AESKey, iv)

	// HMAC stuff
	hmac := userlib.NewHMAC(t.HMACKey)

	saltsIVCipherText := make([]byte, saltsIVCipherTextLength)

	// Fill in the saltsAndCipherText with both salts, iv and the ciphertext
	copy(saltsIVCipherText[r1Start:r1End], r1)
	copy(saltsIVCipherText[r2Start:r2End], r2)
	copy(saltsIVCipherText[ivStart:ivEnd], iv)
	encStream.XORKeyStream(saltsIVCipherText[cipherTextStart:], userdataJSON)

	// Calculate the HMAC tag and append it
	hmac.Write(t.Location)
	hmac.Write(saltsIVCipherText)
	tagged := hmac.Sum(saltsIVCipherText)

	// Store the encrypted tagged user struct in the data store
	userlib.DatastoreSet(hex.EncodeToString(t.Location), tagged)
}

func initMasterIndexNode(t Tuple) map[string]Tuple {
	// Create empty master index node
	masterIndexNode := make(map[string]Tuple)

	// Convert the master index node to JSON
	masterIndexNodeJSON, err := json.Marshal(masterIndexNode)
	if err != nil {
		panic(err)
	}

	// Store the master index node
	storeUsingTuple(t, masterIndexNodeJSON)

	return masterIndexNode
}

// validMAC reports whether messageMAC is a valid HMAC tag for message.
func validMAC(location, message, messageMAC, key []byte) bool {
	hmac := userlib.NewHMAC(key)

	hmac.Write(location)
	hmac.Write(message)
	expectedMAC := hmac.Sum(nil)

	return userlib.Equal(messageMAC, expectedMAC)
}

// loadMasterIndexNode : Return the master index node for the user.
// If it has been corrupted or deleted, it is reinitialized.
func (userdata *User) loadMasterIndexNode() map[string]Tuple {
	var masterIndexNode map[string]Tuple

	value, err := loadUsingTuple(userdata.MasterIndexNodeTuple)
	if err != nil {
		userdata.MasterIndexNodeTuple = generateTuple()
		return initMasterIndexNode(userdata.MasterIndexNodeTuple)
	}

	if err := json.Unmarshal(value, &masterIndexNode); err != nil {
		panic(err)
	}

	return masterIndexNode
}

func (userdata *User) updateMasterIndexNode(masterIndexNode map[string]Tuple) {
	masterIndexNodeJSON, err := json.Marshal(masterIndexNode)
	if err != nil {
		panic(err)
	}

	storeUsingTuple(userdata.MasterIndexNodeTuple, masterIndexNodeJSON)
}

func (userdata *User) deleteFile(masterIndexNode map[string]Tuple, filename string) {
	indexNodeTuple, ok := masterIndexNode[filename]
	if !ok {
		userlib.DebugMsg("deleteFile: file does not exist, filename: %v", filename)
		panic(errors.New("file does not exist"))
	}
	userlib.DatastoreDelete(hex.EncodeToString(indexNodeTuple.Location))
	delete(masterIndexNode, filename)
	userdata.updateMasterIndexNode(masterIndexNode)
}
