#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :QMainWindow(parent), ui(new Ui::MainWindow){

    ui->setupUi(this);
    setFixedSize( 410, 530);

    ui->textEdit->setGeometry(QRect( QPoint( 10, 445), QSize( 395, 45)));
    ui->label->setGeometry(QRect( QPoint( 10, 355), QSize( 395, 70)));
    ui->label_2->setGeometry(QRect( QPoint( 10, 425), QSize( 20, 30)));
    ui->label_3->setGeometry(QRect( QPoint( 10, 335), QSize( 20, 30)));
    ui->label_4->setGeometry(QRect( QPoint( 120, 330), QSize( 220, 30)));
    ui->label_4->setText( "DEVICE CONSOLE WINDOW");

    //sets up QTs user interface system
    m_button = new QPushButton("Send", this);
    m_button->setGeometry(QRect( QPoint( 340, 470), QSize( 60, 30)));

    if(!initEncryption()){

        ui->label->append("sodium libraries failed\r\n");
    }

    //initialises QTs serial port
    serial = new QSerialPort(this); 
    updatetimer = new QTimer(this);

    pbar = new QProgressBar(this);
    pbar->setGeometry(QRect( QPoint( 10, 345), QSize( 390, 10)));
    pbar->setMinimum(0);
    pbar->hide();

    //QT API maps signals from GUI objects to functions
    connect( serial, SIGNAL(readyRead()), this, SLOT(readSerial()));
    connect( m_button, SIGNAL (released()),this, SLOT (SerialSend()));
    connect( updatetimer, SIGNAL( timeout()), this, SLOT(updateJobs()));

    tb = new QTabWidget(this);
    tb->setGeometry(QRect( QPoint( 5, 25), QSize( 400, 320)));
    tb->addTab( etools, tr("Encryption Tools"));
    tb->addTab( &pman, tr("Password Manager"));
    tb->addTab( &test, tr("Testbed"));

    //sets frequency to call 'updateJobs' to every 200 micro seconds
    updatetimer->start(200);
}

MainWindow::~MainWindow(){

    delete ui;
    serial->close();
}

//data is collected from the dongle once tests have been started, the threaded timer function is used to collect the
//information so that the serial buffer is not overloaded and the gui remains responcive while data is being collected
void MainWindow::updateJobs(){

    //handles test function operations
    if(test.random){

        RNGTest();
    }else if(test.fuzz){

        FuzzTest();
    }else if(test.cca){

        CCATest();
    }else if(test.whitebox){

        BlackboxTest();
    }

    //Manages etools tab for adding channels, Creates a new public key with Add Contact
    if(etools->AC.addingkey){

        qDebug()<<"Adding Key";
        ui->label->append("Adding Key");
        crtRecord(etools->AC.contactname);
        updateKeys();
        etools->AC.addingkey = false;
    }

    //makes a request for a selected key with data from etools get key GUI tab
    if(etools->SK.requestkey){

        qDebug()<<"Getting Public Key";
        ui->label->append("Getting Public Key");
        sendData("<get><",">", etools->SK.selection.toStdString().c_str(), etools->SK.selection.length());
        etools->SK.requestkey = false;
        updateKeys();
    }

    //Adds a Public key to the device to create a secure channel, this is accessed by etools GUI tab
    if(etools->GK.sendkey){

        qDebug()<<"Adding Public Key To Create A Secure Channel";
        ui->label->append("Adding Public Key To Create A Secure Channel");
        sendData("<add><" + etools->GK.channel_name + "-",">", etools->GK.publickey, 32);
        etools->GK.sendkey = false;
        updateKeys();
    }

    //handles the encryption and decryption options from the encryption tools GUI tab
    if(!etools->wait){

        etoolsDialog();
    }

    //connects USB device, detects new connections and will detect disconnections
    resetConnection();
}


void MainWindow::Ping(){

    serial->flush();
    serial->write("<ping>");
}

void MainWindow::SerialSend(){

    serial->flush();
    QString message = ui->textEdit->toPlainText();
    serial->write( message.toStdString().c_str(), message.size());
    qDebug()<< "sending" << message;
    ui->label->append(message);
}

//sends public key to dongle with username
void MainWindow::SerialSendKey( QString usernm){

    serial->flush();
    serial->write("<add><", 6);
    serial->write( usernm.toStdString().c_str(), usernm.length());
    serial->write( "-");
    serial->write((char*)publickey, 32);
    serial->write(">");
    serial->flush();
}


void MainWindow::etoolsDialog(){

    //this block of logic deals with a call to encrypt a file
    if(etools->encrypting && !etools->decrypting){

        //create containers for the key, the nonce and the file to encrypts data
        unsigned char randomkey[32];
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        unsigned char binarydata[etools->filesize];

        //generate a secure random number in the randomkey and nonce containers
        randombytes_buf( randomkey, 32);
        randombytes_buf( nonce, crypto_secretbox_NONCEBYTES);

        //write the file bytes to the binarydata array
        memcpy( binarydata, etools->filebytes, etools->filesize);

        //this array will store the encrypted file
        unsigned char tmpfile[etools->filesize];

        //encrypt the file with libsodium secret box function using randomly generated number as a key
        if(crypto_secretbox_easy( tmpfile, binarydata, etools->filesize, nonce, randomkey) == 0){

            ui->label->append("data encrypted...");
            ui->label->append("contacting hardware device...");

            //send the secure random key value to be encypted by the connected device
            serialEncrypt( etools->selection, randomkey, 32);

            //makes sure no more calls to encrypt are started while the encryption process is running
            etools->wait = true;

            //write encrypted file to QByteArray so as to prepend data that will be recieved from serialconnection
            encryptedfile.resize(etools->filesize);
            memcpy( encryptedfile.data(), tmpfile, etools->filesize);

            //prepend nonce data to file, note that its being written backwards because its being prepended
            encryptedfile.prepend("<nonce-end>");
            for(int x = crypto_secretbox_NONCEBYTES; x > 0 ; x--){

                    encryptedfile.prepend(nonce[x]);
            }

            encryptedfile.prepend("<nonce>");
        }else{

            qDebug()<<"encryption failed";
        }
    }

    //this block of logic deals with a call to decrypt the file
    if(etools->decrypting && !etools->encrypting){

        //load file data onto byte array
        encryptedfile.clear();
        encryptedfile.append(etools->filebytes);

        //parse data from decrypted byte array for sending to device
        serialDecrypt();
    }
}

void MainWindow::updateKeys(){

    etools->channelSelect->clear();
    etools->SK.combobox->clear();
    test.channelSelect->clear();

    //sends request for a list of channels
    serial->write( "<lst><channels>", 15);
    serial->write("<lst><rcpients>", 15);
}

void MainWindow::resetConnection(){

    //connects to dongle on detection
    if(!serial->isOpen()){

        //initialising serial functionality
        serial->setPortName(ScanSerialPorts());
        serial->setBaudRate(QSerialPort::Baud9600);
        serial->setDataBits(QSerialPort::Data8);
        serial->setParity(QSerialPort::NoParity);
        serial->setStopBits(QSerialPort::OneStop);
        serial->setFlowControl(QSerialPort::NoFlowControl);
        serial->open(QIODevice::ReadWrite);

        if(serial->isOpen()){

            QThread::usleep(1000);
            updateKeys();
        }
    }
}


//when serial data is recieved it is processed by the following logical structure
void MainWindow::readSerial(){

    //get data incoming to serial
    QByteArray qba;
    qba = serial->readAll();

    //deal with incoming serial data if data contains specific headers
    //each block should have a try catch statment built into it
    //if pong has been recieved from serial
    if(qba.mid(0,10) == "<rcpients>"){

        //initialise the combobox with the tags trimmed off
        QString recipients = (QString)qba.mid( 11, qba.length() - 14);
        etools->SK.updateComboBox(recipients);
    //add each item to the vector list of services
    }else if(qba.mid(0,9) == "<srvices>"){

    //this returns a list of channels, that is both the recipients key and a public and secret key
    }else if(qba.mid(0,10) == "<channels>"){

        //update a list of completed channels
        QString channelNames = (QString)qba.mid( 11, qba.length() - 14);
        etools->updateComboBox(channelNames);
        test.updateComboBox(channelNames);

    //if the header ciphertext is recieved process the following cipher and tag
    }else if(qba.mid(0,11) == "<publickey>"){

        QString key = etools->SK.selection + "-" +(QString) qba.mid( 11, qba.length() - 15).toBase64();
        ui->label->append("Public key: " + key + " copied to clipboard");
        clipboard->setText(key);

    //if the header ciphertext is recieved process the following cipher and tag
    }else if(qba.mid(0,16) == "<initialisation>"){

        //convert the incoming array to unsinged char
        QByteArray qteensypub = qba.mid( 18, 32);
        memmove( teensykey, qteensypub, 32);

        //send public key to dongle, it will store it if it does not
        //allready have it
        SerialSendKey("QT_APP");

        ui->label->append("public key recieved from device");
        qDebug()<<"public key recieved from device";


    }else if(qba.mid(0,8) == "<random>"){

        QByteArray random = qba.mid( 9, qba.size() - 12);
        ui->label->append(random.toBase64());

        if(!test.random){

            clipboard->setText(random.toBase64());
         }else{

            test.rndns << random;
        }

    }else if(qba.mid(0,9) == "<testenk>"){

        //on reciept of the encrypted text
        test.original_cipher.append(qba.mid( 10, qba.size()-13));

    }else if(qba.mid(0,9) == "<testdek>"){

        ui->label->append(qba.mid( 10, qba.size()-13).trimmed().toStdString().c_str());
        test.avalaunch << qba.mid( 10, qba.size()-13).trimmed().toStdString().c_str();

    }else if(qba.mid(0,9) == "<testTAG>"){

        //on reciept of tag
        test.TAG.append(qba.mid( 10, qba.size()-13).trimmed().toStdString().c_str());
        test.obtained_cipher = true;
        test.cca = true;
    }else if(qba.mid(0,12) == "<cipherdata>"){

        //get the size of the cipherdata, this is also the additional authenticated data
        cipherdata_size = qba.size();
        additionaldata = qba.mid( 13, cipherdata_size);

        //name follows header and is the only resizable string recieved
        //therefore it will be between the indexes 13 and 31
        recipientname = (QString)qba.mid( 13, cipherdata_size - 28);
        name = qba.mid( 13, cipherdata_size - 28);
        qDebug()<<"name:" << name;

        //convert qbyte array into a uint8_t array as it was when it was sent
        uint8_t charcdata[ cipherdata_size];
        memmove( charcdata, qba, cipherdata_size);

        //the nonce will 12 bytes long and start after the recipients name
        memmove( nonce, qba.mid( 13 + recipientname.size()), 12);

        //create the authdata to pass into decryption algorithms args
        authdata_size = recipientname.size() + 12;
        authdata = qba.mid( 13, authdata_size);

        //all cipher data has been sent and auth data can be constructed
        cipherflag = true;
        qDebug()<< "cipher data obtained, size:" << cipherdata_size;

    //the following block works once the auth data has been collected, the function
    //generates a session key and parses out the cipher text from the byte array
    //then decrypts the text.
    }else if(qba.mid(0,10) == "<authdata>"){

        //parse the auth tag
        qtag = qba.mid( 11, 27);
        authflag = true;
        qDebug()<< "auth data obtained, size:" << qtag.size();

    //when the actual cipher text comes then the cipher data and auth data
    //should have been obtained, this block uses the data to decrypt the message
    }else if(qba.mid(0,12) == "<ciphertext>"){

        //parse ciphertext from the string and set the correct size
        QByteArray qcipher = qba.mid( 13, messagesize);
        qDebug() << "ciphertext obtained, size:" << qcipher.size();

        //create the encrypted file with each part of the recieved data appended to it and append
        //the total size of the recieved data to that
        if( etools->encrypting){

            ui->label->append("adding cipher data to binary");
            qDebug()<<"adding cipher data to binary";

            //prepend encrypted key to encrypted file data           
            encryptedfile.prepend("<tag-end>");
            encryptedfile.prepend(qtag);
            encryptedfile.prepend("<tag>");

            encryptedfile.prepend("<cipher-end>");
            encryptedfile.prepend(qcipher);
            encryptedfile.prepend("<cipher>");

            //prepend additional data
            encryptedfile.prepend("<additional-end>");
            encryptedfile.prepend(additionaldata);
            encryptedfile.prepend("<additional>");

            //prepend the name of the encryption channel
            encryptedfile.prepend("<name-end>");
            encryptedfile.prepend(name);
            encryptedfile.prepend("<name>");

            //get url of file and convert it into string for file creation
            qDebug()<< "creating file @ " << etools->url.path();
            QFile file(etools->url.path() + ".encrypted");

            if (!file.open(QIODevice::WriteOnly)){

                qDebug()<<"cannot create a new file, check permissions";
            }else{

                //create the new file
                file.write(encryptedfile, encryptedfile.size());
                file.close();
                ui->label->append("creating new encrypted file: " + etools->url.path() + ".encrypted");
                qDebug()<<" created new encrypted file";
            }

            //clear the data off the array;
            encryptedfile.clear();
            etools->encrypting = false;
            etools->wait = false;

        //decrypt incoming
        }else{

            //create a session key and initialise it
            unsigned char key[32];
            createSessionKey(key);

            unsigned char cipher[messagesize];
            memmove( cipher, qcipher, messagesize);

            //also parse the auth data stored in the qbyte array
            unsigned char _auth[authdata_size];
            memmove( _auth, authdata, authdata_size);

            //parse tag
            unsigned char tag[16];
            memmove( tag, qtag, 16);

            //create a variable to store the decrypted text and its size
            unsigned char decrypted[messagesize];

            //decrypt the text and return test data
            if (messagesize == 0 || !authflag || crypto_aead_aes256gcm_decrypt_detached(
                        decrypted, NULL, cipher, (unsigned long long)messagesize,
                        tag, _auth, authdata_size, nonce, key) == -1) {

                ui->label->append("message failed integrity check");
                qDebug()<< "-message failed integrity check-";

                //output to test file

            }else{

                qDebug()<<"decrypted inbound message";
                checkVariables("decrypted", decrypted, messagesize);               
            }
        }

    //decrypts file with recieved decrypted random key
    }else if(qba.mid( 0, 5) == "<dec>"){

        //get decrypted random key
        unsigned char decryptionkey[32];
        memcpy( decryptionkey, qba.mid( 6, 32), 32);

        //extract nonce from encrypted file
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        QByteArray qnonce = subqarray( "<nonce>", "<nonce-end>", encryptedfile);
        memcpy( nonce, qnonce, crypto_secretbox_NONCEBYTES);

        //extract encrypted file itself
        QByteArray qfilebytes = encryptedfile.mid( encryptedfile.indexOf( "<nonce-end>") + 11);
        unsigned long long filesize = qfilebytes.length();
        unsigned char ufilebytes[filesize];
        unsigned char udecrypted[filesize - crypto_secretbox_MACBYTES];
        memcpy( ufilebytes, qfilebytes, filesize);

        //decrypt the file with the recently decrypted string
        if(crypto_secretbox_open_easy( udecrypted, ufilebytes, filesize, nonce, decryptionkey) == 0){

            //get url of file and convert it into string for file creation
            QString path = etools->url.path();
            path.replace( ".encrypted", "");
            qDebug()<< "creating file @ " << path;
            QFile file(path);

            //write decrypted text to file
            if (!file.open(QIODevice::WriteOnly)){

                qDebug()<<"cannot create a new file, check permissions";
            }else{

                //create the new file
                QByteArray qdecrypted;
                qdecrypted.resize(filesize);
                memcpy( qdecrypted.data(), udecrypted, filesize);
                file.write(qdecrypted, filesize - crypto_secretbox_MACBYTES);
                file.close();
                ui->label->append("creating new decrypted file: " + path);
                qDebug()<<" created new decrypted file";
            }
        }else{

            qDebug()<< "error decrypting file";
            ui->label->append("error decrypting file");
        }
    }

    //process non serial protocol data
    if(qba != "pong"){

        qDebug()<< "Recieved:" << qba;
    }else if(test.fuzz){

        test.lastping = 0;

        if(qba != "pong"){

            qDebug()<< "Fuzz test produced:" << qba;
            test.fuzzResult << qba;
        }
    }
    if(test.whitebox){

        //store incoming blackbox test data and set flag to not expect another message
        test.whiteboxList << qba;
        test.expecting = false;
    }

    serial->flush();
}

//encrypts plaintext and sends via serial
void MainWindow::serialEncrypt( QString name, unsigned char *plaintext, int size){

    //allows key to be created
    cipherflag = true;
    recipientname = name;

    //if this function is called so as to encrypt a plaintext key
    if(etools->encrypting){

        serial->write("<enc>-recipient-");
        serial->write(name.toStdString().c_str());
        serial->write("-/recipient-");
        sendData("-plaintext-", "-/plaintext-", plaintext, size);
        serial->write("-end-encryption<enc>");
    }
}

//get data off file and  then send to device for decryption
void MainWindow::serialDecrypt(){

    qDebug("decrypting file");

    //extracting recipient name from file
    name = subqarray( "<name>", "<name-end>", encryptedfile);

    //initialize additional data
    additionaldata = subqarray( "<additional>", ">\r\n<additional-end>", encryptedfile);

    //extract tag from cipher data
    qtag = subqarray("<tag>", ">\r\n<tag-end>", encryptedfile);

    //get encrypted version of key to send
    QByteArray qciphertext = subqarray( "<cipher>", ">\r\n<cipher-end>", encryptedfile);

    //sends decryption data stored on the encrypted file
    sendData( "<dec>-recipient-", "-/recipient-<dec>", name, name.size());
    sendData( "<dec>-authdata-", "-/authdata-<dec>", additionaldata, additionaldata.size());
    sendData( "<dec>-tag-", "-/tag-<dec>", qtag, qtag.length());
    sendData( "<dec>-cipherdata-", "-/cipherdata-<dec>", qciphertext, qciphertext.length());
    serial->write("<dec>-end-decryption<dec>");

    //key can no longer be created
    cipherflag = false;
    recipientname = "";
    etools->decrypting = false;
}

//tells dongle to create a username and password record with same name as in args to serial connection
void MainWindow::crtRecord(QString name){

    serial->flush();
    serial->write( "<crt><", 6);
    serial->write( name.toStdString().c_str(), name.length());
    serial->write( ">", 1);
    serial->flush();
}

//sends a header in args1 followed by qbytearray in args2 and its size in args3 to serial connection
void MainWindow::sendData( QString header, QString footer, QByteArray qarr, int data_size){

    unsigned char data[data_size];
    memcpy( data, qarr, data_size);
    sendData( header, footer, data, data_size);
}

//sends a header in args1 followed by an unsigned char array in args2 and its size in args3
void MainWindow::sendData( QString header, QString footer, unsigned char* array, int data_size){

    serial->flush();
    serial->write(header.toStdString().c_str(), header.length());
    serial->write((char*)array, data_size);
    serial->write(footer.toStdString().c_str(), footer.length());
    serial->flush();

    QThread::msleep(50);
}

//debug function for checking contents and integrity of an unsigned char array
void MainWindow::checkVariables(QString name, unsigned char* checkArr, int arrsize){

    QString out = "uint8_t " + name + "["+ QString::number(arrsize) +"]: ";
    for(int x = 0; x < arrsize; x++){

        out += (QString)checkArr[x] + " ";
        //out += QString::number((uint8_t)checkArr[x]) + " ";
    }

    qDebug()<<out + ". " + name + " test concluded.";
}

//finds text between first two arguments and returns as a qbyte array
QByteArray MainWindow::subqarray( QString header, QString footer, QByteArray arr){

    QByteArray temp = arr.left(arr.indexOf(footer));
    return temp.mid(temp.indexOf(header) + header.size(), temp.size());
}

//requests a random numbers
void MainWindow::collectRand( int length){

    const char* s = std::to_string(length).c_str();
    serial->write( "<ran><", 6);
    serial->write( s, sizeof(s));
    serial->write( ">", 1);
    serial->flush();
}

//creates a public and private key and requests the dongles public key afterwards
//the dongle replies by sending the public key over the serial connection which
//initialises the hostkey variable, then secure communication can begin.
void MainWindow::innitKeys(){

    randombytes_buf( secretkey, sizeof(secretkey));
    crypto_scalarmult_base( publickey, secretkey);
}

//returns a session key to args if cipher data has been recieved
void MainWindow::createSessionKey( unsigned char* key){

    if( cipherflag){

        //use the keys to generate a shared secret key
        unsigned char sharedsecret [crypto_scalarmult_BYTES];

        if(crypto_scalarmult( sharedsecret, secretkey, teensykey) != 0){

            ui->label->append("unable to create a shared key");
            qDebug()<< "-unable to create a shared key-";
        }else{

            qDebug()<< "shared secret generated";
        }

        //use BLAKE2b to hash the generated secret key
      //  unsigned char key[crypto_generichash_blake2b_BYTES];
      //  crypto_generichash_state state;
      //  crypto_generichash_init(&state, sharedsecret, 32, 32);
      //  crypto_generichash_update(&state, teensykey, 32);
      //  crypto_generichash_update(&state, publickey, 32);
      //  crypto_generichash_final(&state, sharedsecret, 32);

        //copy key data to pointer in args
        memmove( key, sharedsecret, 32);
    }
}

//QString is for text only!!! loook at your other shit you done this
bool MainWindow::initEncryption(){

    //initialise sodium libraries
    if (sodium_init() == -1) {

        return false;
    }else{

        return true;
    }
}

//finds the port that the teensyduino is on and returns its name
QString MainWindow::ScanSerialPorts(){

    foreach(const QSerialPortInfo &serialPortInfo, QSerialPortInfo::availablePorts()){

        if(serialPortInfo.manufacturer() == "Teensyduino"){

            location = serialPortInfo.systemLocation();
            qDebug()<<"Teensy found at " + location;
            break;
        }
    }

    return location;
}


// -------------------  RANDOM NUMBER TESTS  ---------------------------
void MainWindow::RNGTest(){

    //checks to see if data has been collected of the test has been set to true
    if(test.rndns.size() >= test.ranCount()){

        ui->label->append("Creating " + QString::number(test.ranLength()) + " by " + QString::number(test.ranCount()) + " bitmap image based on random numbers");
        test.drawPixels("random " + QString::number(test.ranLength()) + " by " + QString::number(test.ranCount()) + " Dispersion");

        ui->label->append("analysing randomness of individual bits");
        test.countOnes(test.rndns);
        test.countBytes(test.rndns);

        ui->label->append("analysing randomness of individual bytes");

        //call the tests to work with the collected data
        test.random = false;
        pbar->hide();
        test.runtest_button->show();
        if(test.latexbunt){

            test.writeLatexFile("RandomTest");
        }

    }else if(test.rndns.size() <= test.ranCount()){

        //create a loading bar n use it
        collectRand( test.ranLength());
        pbar->show();
        pbar->setMaximum(test.ranCount());
        pbar->setValue(test.rndns.size());

    }
}


// ----------------------  CRYPTOGRAPHIC MALLIABILITY TEST  ------------------------------
void MainWindow::CCATest(){

    if(test.avalaunch.size() >= test.field->toPlainText().length()){

           // //gets text from array and formats to be shown on a tex table, also, only need to show a sample of the feedback
           for(int x = 0; x < test.avalaunch.size(); x++){

                QString entry = test.avalaunch.at(x);
                entry.replace( '-', " & ");
                test.Latex << entry;
                test.Latex << "\\\\ \n";
                test.Latex <<" \\hline \n";
           }

            test.cca = false;
            test.runtest_button->show();

            //write the finished  latex code
            test.Latex << "\\hline \n";
            test.Latex << "\\end{tabular} \n";
            test.Latex << "\\end{center} \n" ;


            //flag the test as over
            pbar->hide();
            qDebug()<<" Cryptographic Test Concluded";
            ui->label->append("Cryptographic Malliability Test Concluded");

            if(test.latexbunt){

                test.writeLatexFile("MalliabilityTest");
            }

        //if the total number of decrypted cipher texts has not been obtained manipulate a new char on the ciphertext and send
        }else if(test.avalaunch.size() <= (test.field->toPlainText().length()-1) &&  test.obtained_cipher){

        //get array data initialised for following operations
        QByteArray cipher;
        cipher.append(test.original_cipher);

            //first time round skip the bit manipulation
            if(test.avalaunch.size() != 0){

                //takes a byte from the byte array flips a random bit and inserts it back onto the array
                unsigned char theByte = cipher[test.avalaunch.size()];
                theByte ^= ( 1 << rand() % 4);
                QByteArray newbyte;
                newbyte.append(theByte);
                cipher.remove( test.avalaunch.size()/8, 1);
                cipher.insert( test.avalaunch.size()/8, theByte);
            }

        //get name of channel to test encryption for
        const char* channel = test.channelSelect->currentText().trimmed().toStdString().c_str();

        //send altered data to device for decryption
        serial->write("<dek><", 6);
        serial->write(channel);
        serial->write( "-", 1);
        serial->write(cipher);
        serial->write( "@", 1);
        serial->write( test.TAG);
        serial->write( ">", 1);
        serial->flush();

        pbar->setValue(test.avalaunch.size());

    //crypto test starts
    }else if(test.cca && !test.obtained_cipher){

        serial->write( "<enk><", 6);
        serial->write(test.channelSelect->currentText().toStdString().c_str());
        serial->write("-", 1);
        serial->write(test.field->toPlainText().toStdString().c_str());
        serial->write( ">", 1);

        //wait for ciphertext to be obtained
        test.cca = false;

        //start the progress bar
        pbar->show();
        pbar->setMaximum(test.field->toPlainText().length());

        //Updating strings for latex output
        test.Latex << "Testing for malliability by ";
        test.Latex << "Sending variations of " + test.field->toPlainText();
        test.Latex << " with just one bit flipped and checking if the \\device rejects it";
        test.Latex << "\\begin{center} \n";
        test.Latex << "\\begin{tabular}{||C|C||} \n";
        test.Latex << " \\hline \n";
        test.Latex << "Sent & Authentication \\\\ \n";
        test.Latex << "\\hline \n";
    }
}

//  ------------------------------  FUZZ TEST  --------------------------------------
void MainWindow::FuzzTest(){

    if(!test.startedTimer){

        qDebug()<<"starting fuzz test";
        test.Latex << "\\subsubsection{Fuzzing for " + test.fuzztimeSelect->currentText() + "} ";
        test.timer.start();
        test.startedTimer = true;
        pbar->show();
        pbar->setMaximum(test.fuzzTime());
    }

    const char *fuzzstring = test.nextFuzz().toStdString().c_str();
    ui->label->append(fuzzstring);
    serial->write( "<", 1);
    serial->write(fuzzstring);
    serial->write( ">", 1);

    pbar->setValue(test.elapsedTime);
    test.updateTimer();

    //end progress bar for fuzz test
    if(test.fuzzdone){

        pbar->hide();
        qDebug()<<"fuzzing finished";
        ui->label->append("Fuzzing complete");
        test.fuzz = false;
        test.runtest_button->show();

        //if there is any output while fuzzing record it in a table - though it is usually very unlikley
        if(test.fuzzResult.size() > 0){

            test.Latex << "\\begin{center} \n";
            test.Latex << "\\begin{tabular}{||C|C||} \n";
            test.Latex << "\\hline \n";
            test.Latex << "Recent Fuzz Strings Sent & Result From Sent Strings";
            test.Latex << "\\hline \n";

            for(int x = 0; x < test.fuzzResult.size(); x++){
                for(int r = 0; r < 4; r++){

                    test.Latex << test.fuzzResult.at(x) + " & " + test.liveFuzzStrings.at( (x/4) + r);
                    test.Latex << "\\\\ \n\\hline \n";
                }
            }

            test.Latex << "\\hline \n";
            test.Latex << "\\end{tabular} \n";
            test.Latex << "\\end{center} \n";
        }else{

            test.Latex << "No exceptional behaviour detected.";
        }

        if(test.latexbunt){

            test.writeLatexFile("FuzzTest");
        }
    }
}

// --------------------------------    BLACKBOX TEST    ---------------------------------------
void MainWindow::BlackboxTest(){

    pbar->show();
    pbar->setMaximum(6);
    if(!test.expecting && test.blackcount < 7){

        serial->write( test.whiteboxCommands.at(test.blackcount).toStdString().c_str());
        test.expecting = true;
        pbar->setValue(test.blackcount);
        test.blackcount++;
    }

    if(test.blackcount >= 6){

        pbar->hide();
        test.blackcount = 0;
        test.whitebox = false;

        if(test.latexbunt->isChecked()){

            test.Latex << "Blackbox testing";
            test.Latex << "\\begin{center} \n";
            test.Latex << "\\begin{tabular}{||C|C||} \n";
            test.Latex << " \\hline \n";
            test.Latex << "Sent & Recieved \\\\ \n";
            test.Latex << "\\hline \n";

            //adds test results test output
            for(int x = 0; x < test.whiteboxList.size(); x++){

                //adds data to latex folder and also shows multiple copies of command
                //sent if something is wrong
                test.Latex << test.whiteboxCommands.at(x) + " & " + test.whiteboxList.at(x) + "\\\\ \n";
                test.Latex << "\\hline \n";
            }

            test.Latex << "\\end{center} \n";
            test.Latex << "\\end{tabular} \n";
            test.Latex << "\\hline \n";
            test.writeLatexFile("BlackboxTest");
        }
    }
}

