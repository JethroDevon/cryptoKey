#include "encryptiontools.h"
#include "ui_encryptiontools.h"


EncryptionTools::EncryptionTools(QWidget *parent) :QWidget(parent), ui(new Ui::EncryptionTools){

    channelSelect = new QComboBox(this);
    channelSelect->setGeometry(QRect( QPoint( 10, 120), QSize( 150, 30)));

    encrypt_button = new QPushButton( "Encrypt", this);
    encrypt_button->setGeometry(QRect( QPoint( 170, 120), QSize( 70, 30)));

    decrypt_button = new QPushButton( "Decrypt", this);
    decrypt_button->setGeometry(QRect( QPoint( 250, 120), QSize( 70, 30)));

    field = new QTextEdit("", this);
    field->setGeometry(QRect( QPoint( 10, 60), QSize( 370, 50)));

    explain = new QLabel("Set up a secure channel, select it, then drag and drop a file\nor enter path in the text field below to Encrypt or Decrypt it", this);
    explain->setGeometry(QRect( QPoint( 10, 0), QSize( 370, 60)));

    //tab widget setup
    tb = new QTabWidget(this);
    tb->setGeometry(QRect( QPoint( 5, 155), QSize( 390, 135)));
    tb->addTab( &AC, tr("Create Public Key"));
    tb->addTab( &SK, tr("Get Public Key"));
    tb->addTab( &GK, tr("Add Public Key"));

    connect( encrypt_button, SIGNAL (released()),this, SLOT (encrypt()));
    connect( decrypt_button, SIGNAL (released()),this, SLOT (decrypt()));
}



void EncryptionTools::updateComboBox(QString item){

    //clear and update whole list
    channelSelect->addItem(item);
}


void EncryptionTools::encrypt(){

    selection = channelSelect->currentText();

    //parse file address
    QString fileLocation = field->toPlainText();
    fileLocation.trimmed();
    url = fileLocation.trimmed();
    QFile file(url.path());

    //open file
    if(file.exists() && file.open(QIODevice::ReadOnly) && selection != ""){

          filebytes = file.readAll();
          filesize = filebytes.size();
          file.close();

          //encryption can go ahead
          encrypting = true;

    }else if(!file.exists()){

        field->setText("Problem accessing file at " + fileLocation);
    }if(selection == ""){

        field->setText("please select a channel");
    }
}

//decrypts an existing file
void EncryptionTools::decrypt(){

    //parse file address
    QString fileLocation = field->toPlainText();
    fileLocation.trimmed();
    url = fileLocation.trimmed();
    QFile file(url.path());

    //open file
    if(file.exists() && file.open(QIODevice::ReadOnly)){

          filebytes = file.readAll();
          filesize = filebytes.size();
          file.close();

          //encryption can go ahead
          decrypting = true;

    }else if(!file.exists()){

        field->setText("Problem accessing file at " + fileLocation);
    }
}



EncryptionTools::~EncryptionTools(){

    delete ui;
}
