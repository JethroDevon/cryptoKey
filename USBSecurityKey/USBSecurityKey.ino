/*-----------------------------------------------------------------------------------------------*
 *                                     APPENDIX                                                  *
 *-----------------------------------------------------------------------------------------------*
 *                                                                                               *
 *         Includes  .......................................................  99                 *
 *         Global Variables  ............................................... 108                 *
 *         Protocol Data Class ............................................. 146                 *
 *           processIncoming(char) ......................................... 156                 * 
 *           initRecipient() ............................................... 197                 *
 *           resetProtocol ................................................. 209                 *
 *           int findStringPos(String) ..................................... 220                 *
 *           getSubArray( int, int, uint8_t*) .............................. 256                 *
 *	     int getSubArraySize( String, String) .......................... 271                 *
 *                                                                                               *
 *	   setup() ......................................................... 290                 *
 *	   loop() .......................................................... 318                 *
 *                                                                                               *
 *                                                                                               *
 *                                Device to Host                                                 *
 *                                                                                               *
 *	   wrapSerialMessage( const char*, uint8_t*, size_t) ............... 338                 *
 *	   wrapSerialMessage( String, String) .............................. 349                 *
 *	   testArray( String, uint8_t*, int) ............................... 357                 *
 *                                                                                               *
 *                                                                                               *
 *                     Get From Database and Store on Database                                   *
 *                                                                                               *
 *	   sendList(const char*) ........................................... 373                 *
 *	   addListItem( const char*, String) ............................... 400                 *
 *	   removeFromList( const char*, String) ............................ 420                 *
 *	   addRecord( const char*, const char*, const char*) ............... 459                 *
 *         addRecord( String, String, uint8_t*) ............................ 477                 *
 *         getRecord( uint8_t*, String, String) .............................508                 *
 *	   deleteRecord(String) ............................................ 532                 *
 *                                                                                               *
 *                                                                                               *
 *                               Cryptosystem                                                    *
 *                                                                                               *
 *         initLocalKeys() ................................................. 544                 *
 *	   makeSharedKey( uint8_t*, const char*) ........................... 569                 *
 *	   createKeyPart1(String) .......................................... 583                 *
 *	   createKeyPart2( String, const char*) ............................ 609                 *
 *	   testEncrypt( const uint8_t*, String, int) ....................... 653                 *
 *	   testDecrypt( uint8_t*, String, uint8_t*, int) ................... 678                 *
 *	   encryptIncoming(char) ........................................... 718                 *
 *	   decryptIncoming(char) ........................................... 776                 *
 *                                                                                               *
 *                                                                                               *
 *                           Random Number Generation                                            *
 *                                                                                               *
 *	   updatepool(int) ................................................. 829                 *
 *	   uint8_t randomnessExtractor() ................................... 838                 *
 *	   uint8_t* generateRand(int) ...................................... 869                 *
 *                                                                                               *
 *                                                                                               *
 *                             Host to Device                                                    *
 *                                                                                               *
 *          readSerialInput() .............................................. 886                 *
 *                                                                                               *
 *-----------------------------------------------------------------------------------------------*
 *                                       Information                                             *
 *-----------------------------------------------------------------------------------------------*
 *                                                                                               *
 *	   SD and SPI libraries can be found at www.arduino.cc although should be included       *
 *	   when the IDE or compiler is downloaded.                                               *
 *                                                                                               *
 *	   Cryptographic libraries can be found at https://github.com/rweather with              *
 *	   documentation available at https://rweather.github.io/arduinolibs/                    *
 *                                                                                               *
 *	   This program is to be written to a Teensy microcontroller with an SD module           *
 *	   CS pin soldered to pin 10 on the teensy and accelerometer int pin soldered to         *
 *	   pin 0.                                                                                *
 *                                                                                               *
 *	   The embedded cryptosystem can apply an acceptable level of encryption but the         *
 *	   software is a prototype and the extra testing functionalities do undermine that.      *
 *	                                                                                         *
 *	   Code written with emacs using dark spacemacs theme and comment highlighting.          *
 *                                                                                               *
 *-----------------------------------------------------------------------------------------------*
 *                                          Licence                                              *
 *-----------------------------------------------------------------------------------------------*
 *                                                                                               *
 *            This program is free software: you can redistribute it and/or modify               *
 *            it under the terms of the GNU General Public License as published by               *
 *            the Free Software Foundation, either version 3 of the License, or                  *
 *            (at your option) any later version.                                                *
 *                                                                                               *
 *            This program is distributed in the hope that it will be useful,                    *
 *            but WITHOUT ANY WARRANTY; without even the implied warranty of                     *
 *            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                      *
 *            GNU General Public License for more details.                                       *
 *                                                                                               *
 *            You should have received a copy of the GNU General Public License                  *
 *            along with this program.  If not, see <http://www.gnu.org/licenses/>.              *
 *                                                                                               *
 *                                                                                               *
 *----------------------------------------------------------------------------------------------*/

//includes Arduino cryptography library, SD card library and serial communication library
#include <AES.h>
#include <Curve25519.h>
#include <GCM.h>
#include <BLAKE2b.h>
#include "SD.h"
#include "SPI.h"


//stores generic key size, line added for readability
#define keysize 32

//these flags direct serial data to the appropriate functions
bool comadd, comget, compop, comset, comstart, comsrv, srvusr, srvpas, ecrypt, dcrypt, crtrec, list, resetconnection;
bool rnd, eKrypt, dKrypt, verbose;

//stores incoming serial data 
String message;

//contains a public key that belongs to the security key, will be initialised on startup
uint8_t publickey[keysize];

//random number pointer needs to be global for safe operations when generating random numbers
uint8_t *randout;

//this array will be filled with bytes from the accelerometer xored with other data
uint8_t datapool[256];

//re-suable number as nonce for testing encryption function, simple so test encryption can be analysed
uint8_t nonNonce[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

//tracks number of loops of serial read function for adding timing property to random number generator
int count = 0;

//contains the connection needed to talk to the sd card and initialised in setup()
File records;

/*----------------------------------------------------------------------------------------------*
 *                                       PROTOCOL DATA CLASS                                    *
 *----------------------------------------------------------------------------------------------*  
 *                                                                                              *
 *         This class will will collect all data intended for encryption and decryption.        *
 *              processIncoming() will return true once data collected contains all             *
 *                        that is needed to complete encryption process.                        *
 *                                                                                              *
 * Program will not encrypt or decrypt data if the entire protocol required exceeds 1024 bytes  *
 *----------------------------------------------------------------------------------------------*/
class protocolData {

 public:

  //keep track of amount of data that has been passed in while decrypt function has been active
  int charcount = 0, msgsize = 0, rname = 0, authsize = 0, msgpos = 0, tagpos = 0, authpos = 0;
  String recipient;
  char data[1024];

  //gathers incoming data for encryption and decryption returns true when end string detected
  bool processIncoming(char i) {

    data[charcount] = i;
    charcount++;

    //if recieved data was for encryption process data and return true
    if(findStringPos("-end-encryption") > 0){

      initRecipient();
      msgpos = findStringPos("-plaintext-") + 11;
      msgsize = getSubArraySize( "-plaintext-", "-/plaintext-");
   
      return true;   
    }

    //if recieved data was for decryption process data and return true
    if(findStringPos("-end-decryption") > 0){

      initRecipient();
      msgpos = findStringPos("-cipherdata-") + 12;
      authpos = findStringPos("-authdata-") + 10;
      authsize = getSubArraySize( "-authdata-", "-/authdata-");
      msgsize = getSubArraySize( "-cipherdata-", "-/cipherdata-");
      tagpos = findStringPos("-tag-") + 5;

      return true;   
    }

    //if buffer limit reached
    if (charcount > 1024) {

      resetProtocol();

      //a long delay to at least make the device unusable if it is being attacked
      delay(1000);
    }
    
    return false;
  }

  //parses recipient name from data array
  void initRecipient(){

    int rpos = findStringPos("-recipient-") + 11;
    rname = getSubArraySize( "-recipient-", "-/recipient-");

    for(int x = rpos; x < rpos + rname; x++){

      recipient += data[x];
    }
  }

  //securely clear the data buffer reset integers and switch data collecting off
  void resetProtocol(){

    memset( data, 0, 1024);
    charcount = 0,  msgsize = 0, rname = 0, authsize = 0, msgpos = 0, tagpos = 0, authpos = 0;
    dcrypt = false;
    ecrypt = false;
    recipient = "";
  }

  //returns position if string in args is present at the end of the data array -1
  //if it is not found - following strings allow management of data in object
  int findStringPos(String find){

    int memsize = charcount;
    int findsize = find.length() ;

    //searches for substrings in char arrays, optimise later, WARNING; optimisation
    //must consider null bytes in data
    if(findsize <= memsize){
      
      for(int x = 0; x < memsize; x++){

	bool found = false;

	for(int y = 0; y < findsize; y++){
	  
	  if(find.charAt(y) == data[x + y]){

	    found = true;
	  }else{

	    found = false;
	    break;
	  }
	}
	if(found){

	  return x;
	}
      }
    }
    
    return -1;
  }

  //finds data between two strings in data array and writes sub array to args
  //returns true or false depending if two strings have been found
  void getSubArray( int pos, int arraysize, uint8_t *subarray){

    uint8_t array[arraysize];

    //only go ahead with copy if dimensions in args are sound
    if(pos + arraysize <= charcount){
      for( int x = pos; x < pos + arraysize; x++){
	
	array[x-pos] = data[x];
      }
        memcpy( subarray, array, arraysize);
    }
  }

  //returns size of sub array between each substring, minus one if it doesnt exist
  int getSubArraySize( String startstr, String endstr){

    int pos = findStringPos(startstr);

    if(pos < 0){

      return pos;
    }
    
    return (findStringPos(endstr) - pos) - startstr.length();
  }
};


//creates an object from the above class and is used in decrypt functions
//to return true when each part of the decryption protocol has been collected
protocolData pd;

//serial, SD and encryption functionality is initialised when device is started
void setup() {

  //verbosity is for known answer tests, this is set to false at startup
  verbose = false;

  //starts the serial connection at USB speed
  Serial.begin(9600);
  while (!Serial);

  //confirms if the SD card is initialised and therefore usable
  if (!SD.begin(10)) {

    Serial.println("SD fail");
  } else {

    Serial.println("SD pass");
  }

  //tests ramdom numbers and crypto library, bugs have produced results wher
  //both outputs are the same
  uint8_t rand[keysize];
  memcpy( rand, generateRand(keysize), keysize);
  testArray("test rnd" , rand, keysize);
  Curve25519::dh1( rand, rand);
  testArray("test dh1" , rand, keysize);
}

//this is the main loop
void loop() {

  //clears old serial data, enables data to come through one byte at a time
  Serial.flush();

  //constantly parses incoming data for commands
  readSerialInput();

  //collecting data for random number generator to stay updated
  count++;
  if(count > 254)
    count = 0;

 
}

//this function sends a heading in tags eg: '<myHeading>' followed by a message '<amessage>' the
//first argument is the heading the second is the data to send and the last is the size of that data
//there is a limit to the size of the data that can be sent at the moment, this is because the teensy has
//a set buffer size to overcome this if the message is greater than 64 bytes then a stream of data is sent instead
void wrapSerialMessage( const char* heading, uint8_t* data, size_t sizeofdata) {

  Serial.flush();
  Serial.print("<"); Serial.print(heading); Serial.print("><"); Serial.write( data, sizeofdata); Serial.println(">");

  //there must be a long enough delay for the host computer to generate a key and with this particular use case encryption does
  //not have to happen in microseconds and it is possible a delay can protect the dongle from attacks
  delay(10);
}

//overloaded version of above that sends a string instead of a uint8_t*
void wrapSerialMessage( String heading, String data) {

  Serial.flush();
  Serial.print("<"); Serial.print(heading); Serial.print("><"); Serial.print( data); Serial.println(">");
  delay(60);
}

//test each piece of data needed to encrypt / decrypt so I can check against the hosts data
void testArray( String aname, uint8_t* arr, int arrsize) {

  Serial.print("uint8_t ");
  Serial.print(aname);
  Serial.print("[");
  Serial.print(arrsize);
  Serial.println("]: ");
  for ( int x = 0; x < arrsize; x++) {

    Serial.print(" ");
    Serial.print( (uint8_t) arr[x]);
  }
  Serial.print(". ");
}

//sends each item of the list in args over serial one at a time
void sendList( const char* listname) {

  
  String contents;
  
  if (SD.exists(listname)) {

    //dump all data onto string
    records = SD.open( listname);
    while (records.available()) {
     
      char in = (char)records.read();
      contents += in;

      if(in == '>'){

        wrapSerialMessage( listname, contents.substring( 1, contents.length()-1));
        contents = "";
      }
    }

    records.close();
  }
}


//adds string in args 2 to a list with the same name as in args 1
void addListItem( const char* listname, String listitem) {

  
  if (!SD.exists(listname)) {

    records = SD.open( listname, O_CREAT | O_WRITE);
  } else {

    records = SD.open( listname, O_WRITE);
  }
  
  records.print("<");
  records.write( listitem.c_str(), listitem.length());
  records.print(">");
  records.flush();
  records.close(); 
}

//reads each item from the file in args1 to eeprom and then back onto the file without the
//item in args2
void removefromList( const char* listname, String listitem) {

  
  if (SD.exists(listname)) {

    //dump all data onto string
    records = SD.open( listname);
    String contents = "";
    while (records.available()) {

      contents += (char)records.read();
    }
    records.close();

    //search the string for the substring and remove the values
    int found = contents.indexOf(listitem);

    if ( found > -1) {

      contents.remove( found -1, listitem.length() + 2);
    }

    //delete the original file and create a new one with the same name and write to it
    //this must be done carefully so as not to lose data if the SD is disrupted in any way
    records = SD.open( "temp", O_CREAT | O_WRITE);
    records.write( contents.c_str(), sizeof(contents));
    records.flush();
    records.close();
    SD.remove(listname);

    records = SD.open( listname, O_CREAT | O_WRITE);
    records.write( contents.c_str(), sizeof(contents));
    records.flush();
    records.close();
    SD.remove("temp");
  }
}

//stores a username and password for a website or service
void addRecord ( const char* service, const char* username, const char* password) {

  if (SD.exists(service)) {

    Serial.println("rcrd exists");
  } else {

    records = SD.open( service,  O_CREAT | O_WRITE);
    records.print("<username-");
    records.print(username);
    records.print("><password-");
    records.print(password);
    records.print(">");
    records.flush();
    records.close();
  }
}

void addRecord( String dir, String file, uint8_t *data){

  
  String _p = dir + "/" + file;
  const char* directory = dir.c_str();
  const char* path = _p.c_str();
 
  if(SD.exists(directory)){
  

    if(SD.exists(path)){

      Serial.println("record exists");
    }else{

      File file = SD.open( path, O_CREAT | O_WRITE);
      file.write( data, keysize);
      file.flush();
      file.close();
    }
  }else{

    SD.mkdir(directory);
    File file = SD.open( path, O_CREAT | O_WRITE);
    file.write( data, keysize);
    file.flush();
    file.close();
  }
}

//initialises data in the first argument with the database entry at dir and file
void getRecord(uint8_t *data, String dir, String file) {

  if (SD.exists((dir + "/" + file).c_str())) {

    records = SD.open((dir + "/" + file).c_str());

    String contents = "";
    while (records.available()) {

      contents += (char)records.read();
    }
       
    memcpy( data, contents.c_str(), keysize);

  } else {

    Serial.println("no rcrd");
  }

  records.flush();
  records.close();
}

//deletes a database entry
void deleteRecord(String rname) {

  //deletes all possible files before the directory is removed
  SD.remove((rname + "/PUB").c_str());
  SD.remove((rname + "/SEC").c_str());
  SD.remove((rname + "/SES").c_str());
  SD.remove((rname + "/REC").c_str());
  SD.rmdir(rname.c_str());
}

//If the publickey for this device has not been created then create it
//otherwise create one and initialise the global variable "publickey"
void initLocalKeys() {

  //remove the old contact for the host application
  SD.remove("QT_APP");
  SD.remove("localkey");
  
  //create record for local keys
  createKeyPart1("localkey");

  //check if the key has been created successfuly and initialise global
  //public key
  if (SD.exists("localkey")) {

    //getRecord( publickey, "localkey", 1);
    getRecord( publickey, "localkey", "publickey");
    
    wrapSerialMessage( "initialisation", publickey, keysize);
    Serial.println("crypto pass");
  } else {

    Serial.println("crypto fail");
  }
}

//this will be altered to return the hash of the shared key and be renamed to returnkey
void makeSharedKey( uint8_t* sessionkey, const char* recipient) {

  
  uint8_t key[keysize];
  getRecord( key, recipient, "ses");
   
  //hashing temporarily held back for now but key would be hashed here
  //BLAKE2b
  
  memcpy( sessionkey, key, keysize);
}

//Performs part 1 of the diffie hellman key exchange and stores the public and secret keys
//on the database under the name in args
void createKeyPart1(String keyname){

  
  uint8_t _publickey[keysize];
  uint8_t _secretkey[keysize];

  //the secret key is created with a random number
  memcpy( _secretkey, generateRand(keysize), keysize);

  //this sends the random generated number for testing
  if(verbose){

    testArray( "Secret_key", _secretkey, 32);
  }
  
  //this creates the first part of the diffie helman key agreement
  //a public key is made for sharing and a secret key is kept in order to
  //generate new keys shared keys with another agents public key
  Curve25519::dh1( _publickey, _secretkey);

  addRecord( keyname, "pub", _publickey);
  addRecord( keyname, "sec", _secretkey);
  addListItem( "rcpients", keyname);
}

//this function will create an unhashed sessionkey from recieved publickey and a secretkey
void createKeyPart2( String rname, uint8_t *_incomingkey) {

  //can use this block to determine the instegator from the recipient
  //and flip positions of public keys to create better hashing capabilities
  if(!SD.exists(rname.c_str())){

    //augment key creation message for recipient of public key
    Serial.print("new P key");
    createKeyPart1(rname);
  }

  //initialise variables with keys that are to be kept and
  //delete file
  uint8_t secretkey[keysize];
  uint8_t publickey[keysize];
  uint8_t incomingkey[keysize];

  getRecord( secretkey, rname.c_str(), "sec");
  getRecord( publickey, rname.c_str(), "pub");

  deleteRecord(rname);
 
  memcpy( incomingkey, _incomingkey, keysize);
 
  addListItem("channels", rname.c_str());
  addRecord( rname, "pub", publickey);
  addRecord( rname, "rec", incomingkey);

  //creates session key out of incomingkey and secret key
  if(Curve25519::dh2( incomingkey, secretkey)){
  
    addRecord( rname.c_str(), "ses", incomingkey);
    Serial.print("new S key");
  }else{

    Serial.println("Key fail");
  }

  records.flush();
  records.close();
}


//encrypts a string without authentication
void testEncrypt(const uint8_t *plaintext, String recipient, int size){

  //container of encrypted text and computed tag
  uint8_t ciphertext[size];
  uint8_t tag[16];

  //create and initialise the key to encrypt with
  uint8_t sharedkey[keysize];
  makeSharedKey( sharedkey, recipient.c_str());

  //create the Galois Counter Mode of operation object and set it to use the AES256 encryption standard
  GCM<AES256> gcmo;
  gcmo.setKey( sharedkey, keysize);
  gcmo.setIV( nonNonce, sizeof(nonNonce));
  gcmo.encrypt( ciphertext, plaintext, size);
  gcmo.computeTag( tag, 16);
  
  //send the messages wrapped with headers and in the right order so the host can process them
  wrapSerialMessage( "testenk", ciphertext, size);

  //send MAC tag
  wrapSerialMessage( "testTAG", tag, 16);
}

//decrypts a string without authentication
void testDecrypt( uint8_t *ciphertext, String recipient, uint8_t *tag, int size){

  //container for the decrypted cipher and outcome of checking tag label
  uint8_t plaintext[size];
  uint8_t label[9];
  uint8_t outcome[size + 9];

  //create and initialise the sharedkey to decrypt with
  uint8_t sharedkey[keysize];
  makeSharedKey( sharedkey, recipient.c_str());
  
  //create the AES-GCM object
  GCM<AES256> gcmo;

  //now that the appropriate data has been gathered the ciphertext can be decrypted
  gcmo.setKey( sharedkey, keysize);
  gcmo.setIV( nonNonce, sizeof(nonNonce));
  gcmo.decrypt( plaintext, ciphertext, size);
  
  //check the tag for integrity
  if (!gcmo.checkTag(tag, 16)) {

    memcpy( label, "-rejected", 9); 
  } else {

    memcpy( label, "-accepted", 9);
  }

  //append result of decryption 
  memcpy( outcome, plaintext, size);
  for(int x = size; x < size + 9; x++){

    outcome[x] = label[x - size];
  }

  //send decrypted message back
  wrapSerialMessage( "testdek", outcome, size + 9);
}

//is fed data for incoming ciphertext and will return decrypted text to host securley
void decryptIncoming(char incoming) {

  //when data needed to decrypt the cipher text has been gathered decryption can begin
  if (pd.processIncoming(incoming)) {

    //create and initialise the sharedkey to decrypt with
    uint8_t sharedkey[keysize];   
    makeSharedKey( sharedkey, pd.recipient.c_str());
 
    //containers for the decrypted cipher and plain texts to be initialised
    //by the getCiphertext and decrypt functions
    uint8_t plaintext[pd.msgsize];
    uint8_t ciphertext[pd.msgsize];
    pd.getSubArray( pd.msgpos, pd.msgsize, ciphertext);

    //initialise auth data
    uint8_t auth[pd.authsize];
    pd.getSubArray( pd.authpos, pd.authsize, auth);
    
    //initialise the tag
    uint8_t tag[16];
    pd.getSubArray( pd.tagpos, 16, tag);
    
    uint8_t nonce[12];
    pd.getSubArray( pd.findStringPos("-authdata-") + ( 10 + pd.rname), 12, nonce);

    if(verbose){

      testArray( "ciphertext", ciphertext, sizeof(ciphertext));
      testArray( "authdata", auth, sizeof(auth));
      testArray( "tag", tag, sizeof(tag));
      testArray( "nonce", nonce, sizeof(nonce));
      Serial.flush();
    }

    //create the AES-GCM object and pass in decryption protocol data
    GCM<AES256> gcmo;
    gcmo.setKey( sharedkey, keysize);
    gcmo.setIV( nonce, 12);
    gcmo.addAuthData( auth, pd.authsize);
    gcmo.decrypt( plaintext, ciphertext, pd.msgsize);
   
    //check the tag for integrity
    if (!gcmo.checkTag(tag, 16)) {

      //delay stunts possible lunchtime attack
      delay(10);
      Serial.print("<fail>");
    } else {

      Serial.print("<pass>");
      wrapSerialMessage("dec", plaintext, pd.msgsize);
    }
    pd.resetProtocol();
  }
}

//encrypts incoming and returns encrypted data, will later also encrypt for a set recipient
void encryptIncoming( char incoming) {

  //collect data until can encrypt
  if( pd.processIncoming(incoming)){

    //create plaintext and ciphertext containers and initialise plaintext from pd object
    uint8_t ciphertext[pd.msgsize];
    uint8_t plaintext[pd.msgsize];
    pd.getSubArray( pd.msgpos, pd.msgsize, plaintext);

    //create and initialise the key to encrypt with
    uint8_t sharedkey[keysize];
    makeSharedKey( sharedkey, pd.recipient.c_str());

    //generate a nonce for the IV and add it as data to be authenticated when the block is sent
    uint8_t nonce[12];
    memcpy( nonce, generateRand(12), 12);

    //use channel name, the nonce to be used and the size of the ciphertext as authdata, only
    //the channel name contributes to security but rest is convenient anyway
    uint8_t cipherdata[ pd.rname + 12];
    memcpy( cipherdata, pd.recipient.c_str(), pd.rname);
    
    for ( int x = pd.rname; x < pd.rname + 12; x++) {

      cipherdata[x] = nonce[x - pd.rname];
    }
    
    //create the Galois Counter Mode of operation object and set it to use the AES256 encryption standard
    GCM<AES256> gcmo;
    
    //next generate the tag and send that also
    uint8_t tag[gcmo.tagSize()];

    //set the key to encrypt with then set the IV add the auth data and then encrypt
    gcmo.setKey( sharedkey, sizeof(sharedkey));
    gcmo.setIV( nonce, sizeof(nonce));
    gcmo.addAuthData( cipherdata, sizeof(cipherdata));
    gcmo.encrypt( ciphertext, plaintext, pd.msgsize);
    gcmo.computeTag( tag, gcmo.tagSize());
    
    //send the messages wrapped with headers and in the right order so the host can process them
    wrapSerialMessage( "cipherdata", cipherdata, sizeof(cipherdata));
    wrapSerialMessage( "authdata", tag, sizeof(tag));
    wrapSerialMessage( "ciphertext", ciphertext, pd.msgsize);

    pd.resetProtocol();
  }
}


//xors together iterations of readSerialData() with data gathered from the accelerometer
//and updates the datapool with it
void updatepool(int number1){

  for(int i = 0; i < 256; i++){
    
    datapool[i] = (analogRead(0) ^ (number1 / i))%255;
  }
}

//performs von neumanns decorellation to get an integer with a highlevel of randomness
uint8_t randomnessExtractor(){

  int randomnum = 0;
  int bitTotal = 0;

  for(int x = 0; x < 254; x++){

    int vnbyte = datapool[x];

    for(int i = 0; i < 7; i+=2){

      int A = (vnbyte >> i) & 1;
      int B = (vnbyte >> (i+1)) & 1;

      if( A != B){
	 
	randomnum ^= A << bitTotal;
	bitTotal++;
      }
    }

    if(bitTotal > 7){

      break;
    }
  }

  return randomnum;
}

//will generate an array of random numbers of size based in args using random number generator RNG
uint8_t* generateRand(int numsize) {

  uint8_t key[numsize];
  updatepool(randomnessExtractor());
  randomSeed(randomnessExtractor());
  for(int i = 0; i < numsize; i++){

    key[i] = random(254);
  }

  randout = key;
 
  return randout;
}

//very central function to program, will always be parsing data when it is available, uses that data
//to call other functions in program, is the central logic behind the cryptosystem
void readSerialInput() {

  while ( Serial.available() > 0) {

    unsigned char in = Serial.read();

    //if decrypting messages read input
    if(dcrypt){

      decryptIncoming(in);
    }

    //if decrypting messages read input
    if(ecrypt){

      encryptIncoming(in);
    }

    //this block detects if a command is being recieved from serial connection
    if ( in  == '<' && !comstart) {

      comstart = true;
    }

    //once the end of the message character has been found process the message unless the protocol data
    //message requires a '>' as plaintext in which case keep collecting
    if ( in == '>' && comstart) {

      message.remove( 0, 1);

      //each if statement initialises a flag relating to each incoming command, the
      //next incoming data in '<...>' brackets is processed in a way relating to that
      //previously set command, afterwards, the logic is reset ready for the next message
      if ( message == "get" || comget) {

        //sends the public key with the same name as requested via serial from the database
        if (comget) {

          //create a container for a publickey and call getRecord to initialise it with the key known as input
          uint8_t publickey[keysize];
          getRecord( publickey, message, "pub");

          //send that key to the host
          wrapSerialMessage("publickey", publickey, keysize);
          comget = false;
        } else {

          comget = true;
        }
	//a key can be recieved and then stored on the database sending its name followed
	//by a '-' then the key over serial
      } else if ( message == "add" || comadd) {

        if (comadd) {

	  //parse name and key from add protocol message
          String name = message.substring( 0, message.indexOf("-"));
	  
          uint8_t temp[keysize];
          memcpy( temp, (char*)message.substring( message.indexOf("-") + 1, message.indexOf(">")).c_str(), keysize);

	  //complete key exchange protocol
	  createKeyPart2( name.c_str(), temp);
          comadd = false;
        } else {

          comadd = true;
        }
	//deletes a key from the database and also from lists designed to track it
      } else if ( message == "pop" || compop) {

        if (compop) {

	  //remove items from database list
          removefromList( "srvices", message);
          removefromList( "rcpients", message);
	  removefromList( "channels", message);
	
	  //deletes directory with with keys in it
          deleteRecord(message);

	  Serial.println("Dltd " + message);
          compop = false;
        } else {

          compop = true;
        }
	//will be used to change data
      } else if ( message == "srv" || comsrv) {

        if (comsrv) {

          //break up service message into the three components that make up a service ( service, username, password)
          String servicename = message.substring( 0, message.indexOf("@")).c_str();
          String username = message.substring( message.indexOf("@") + 1, message.indexOf("-")).c_str();
          String password = message.substring(message.indexOf("-") + 1).c_str();
          addListItem( "srvices", servicename.c_str());
          addRecord( servicename.c_str(), username.c_str(), password.c_str());
          comsrv = false;
        } else {

          comsrv = true;
        }
	//returns the encrypted username of a service
      } else if ( message == "usr" || srvusr) {

        if (srvusr) {

          //get stored record of usr name from record with input name
          uint8_t user[keysize];
          char input[sizeof(message)];
          message.toCharArray( input, sizeof(input));
	  //  getRecord( user, input, 1);

          //send that data to the host
          wrapSerialMessage("username", user, sizeof(user));
          srvusr = false;
        } else {

          srvusr = true;
        }
	//returns the encrypted password of a sersvice
      } else if ( message == "pas" || srvpas) {

        if (srvpas) {

          uint8_t password[keysize];
          char input[sizeof(message)];
          message.toCharArray( input, sizeof(input));
	  //     getRecord( password, input, 2);
          Serial.print("<");
          Serial.print((char*)password);
          srvpas = false;
        } else {

          srvpas = true;
        }
	//encrypts the following incomimg data
      } else if ( message == "enc" || ecrypt) {

        if (ecrypt) {

          ecrypt = false;
        } else {

          ecrypt = true;
        }
	
	//collects data to decrypt and decrypts the data when the stream ends
      } else if ( message == "dec" || dcrypt) {

        if (dcrypt) {

	  dcrypt = false;
        } else {

          dcrypt = true;
        }
	//creates a new public and secret key record in the database named after first args 
      } else if ( message == "crt" || crtrec) {

        if (crtrec) {
      
          createKeyPart1(message);
          crtrec = false;
        } else {

          crtrec = true;
        }
	//sends a list of either recipients or services depending on request
      } else if ( message == "lst" || list) {

        if (list) {

          sendList(message.c_str());
          list = false;
        } else {

          list = true;
        }
      }if ( message == "ran" || rnd) {

        if (rnd) {

          int size = atoi(message.c_str());
	  uint8_t randomnumber[size];
	  memcpy( randomnumber, generateRand(size), size);
	  wrapSerialMessage("random", randomnumber, size);
	  
          rnd = false;
        } else {

          rnd = true;
        }
      }  else if ( message == "vrb") {

        if (verbose) {

	  Serial.println("vrb off");
          verbose = false;
        } else {

	  Serial.println("vrb on");
          verbose = true;
        }
      } else if ( message == "enk" || eKrypt) {

        if (eKrypt) {

          String rname = message.substring( 0, message.indexOf("-"));
	  int datasize = message.length() - rname.length() -1;
	  uint8_t udata[datasize];
	  memcpy( udata, message.substring( message.indexOf("-") + 1).c_str(), datasize);
	  Serial.flush();
	  testEncrypt( udata, rname, datasize);	  
          eKrypt = false;
        } else {

          eKrypt = true;
        }
      } else if ( message == "dek" || dKrypt) {

        if (dKrypt) {

	  String rname = message.substring( 0, message.indexOf("-"));    	 
	  int datasize = message.length() - (rname.length() + 18);
	  uint8_t udata[datasize];
	  uint8_t utag[16];
	  memcpy( udata, message.substring( rname.length() + 1, message.indexOf("@") + 1).c_str(), datasize);
	  memcpy( utag, message.substring( message.indexOf("@")+1).c_str(), 16);
	  testArray("udata", udata, datasize);
	  Serial.flush();
	  testDecrypt( udata, rname, utag, datasize);	  
          dKrypt = false;
        } else {

          dKrypt = true;
        }
      }else if ( message == "ping") {

        Serial.print("pong");
      }else if ( message == "reset") {

	initLocalKeys();
      }
      
      Serial.flush();
      message = "";
      break;
    }

    //builds up a message string out of each char from the serial buffer
    if (comstart) {

      message.concat((char)in);
    }

    //updates pool of random data
    updatepool(count);
  }
}
