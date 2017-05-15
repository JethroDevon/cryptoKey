#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "encryptiontools.h"
#include "tests.h"
#include "passman.h"

#include <iostream>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QString>
#include <string>
#include <QList>
#include <QStringList>
#include <QMainWindow>
#include <QtSerialPort>
#include <QSerialPortInfo>
#include <QPushButton>
#include <QFile>
#include <QFileInfo>
#include <QByteArray>
#include <QThread>
#include <QProgressBar>
#include <sodium.h>



/********************************************************************

This program is designed to debug and test the code written on the teensy
and also to help plan the finished host application.

*********************************************************************/

namespace Ui {

class MainWindow;
}

class MainWindow : public QMainWindow{

    Q_OBJECT

public:


    //encryption tools dialog object
    EncryptionTools *etools = new EncryptionTools;
    Tests test;
    PassMan pman;

    //following variables store data based on an a cipher that is expected
    uint16_t messagesize;
    unsigned char nonce[12];
    QByteArray nonceII;
    uint16_t cipherdata_size;

    //cipherdata sends two bytes to be used in auth data and to make one 16bit
    //integer, it is cheaper to store them than it is to extract them from it
    //authdata will store data from the cipherdata header as it comes in over
    //serial connection and the auth tag is sent after that but before the cipher text
    uint8_t authbytes[2];
    QByteArray additionaldata;
    QByteArray authdata;
    QByteArray qtag;
    QByteArray name;
    int authdata_size;


    //stores bytes of encrypted file
    QByteArray encryptedfile;

    //qt specific functionality
    explicit MainWindow(QWidget *parent = 0);

    //testing and debugging functions
    void checkVariables( QString, unsigned char*, int);

    //scan usb ports for teensy
    QString ScanSerialPorts();

    //adds a publickey named in args to array
    void crtRecord(QString name);    
    void SerialSendKey( QString);
    void removeKey(QString name);

    //pastes publickey named in args to cursor location
    void pasteKey(QString);

    void createSessionKey( unsigned char*);
    bool initEncryption();
    void serialEncrypt( QString, unsigned char*, int);
    void serialDecrypt();
    void checkConnection();
    void collectRand(int);
    void RNGTest();
    void FuzzTest();
    void BlackboxTest();
    void CCATest();
    void updateKeys();

    //sends data to connection wrapped in first two strings
    void sendData( QString, QString, unsigned char*, int);
    void sendData( QString, QString, QByteArray, int);

    //returns substring of a qbytearray
    QByteArray subqarray( QString, QString, QByteArray);

    //this object will enable writing to the clipboard
    QClipboard *clipboard;

    QSerialPort *serial;
    QTimer *updatetimer;
    QProgressBar *pbar;
    QString location;
    unsigned char publickey[32];
    unsigned char teensykey[32];
    bool pubkeyinit;

    QTabWidget *tb;

    //records the amount of time it takes to recieve pong after sending ping
    int pingtime, jobTime = 0;

    ~MainWindow();

private slots:

    void readSerial();
    void resetConnection();
    void SerialSend();
    void innitKeys();
    void updateJobs();
    void Ping();

    //these functions open dialog boxes and run dialog box related logic
    void etoolsDialog();

signals:

    int mainsignal(int);

private:

    Ui::MainWindow *ui;

    ///rename buttons to much purpose
    QPushButton *reset_button;
    QPushButton *remove_button;
    QPushButton *add_channel_key;
    QPushButton *etools_button;
    QPushButton *test_button;
    QPushButton *m_button;
    QPushButton *t_button;
    QPushButton *d_button;
    QPushButton *c_button;
    QPushButton *k_button;

    //encapsulate sensitive variables in private to obfuscate from binary analyses such as with gdb tool
    unsigned char secretkey[32];
    QString recipientname;

    //if variables based on protocol data for an incoming cipher text
    //have all been initialised this will be true
    bool cipherflag = false;
    bool authflag = false;
};

#endif // MAINWINDOW_H
