#include "getkey.h"
#include "ui_getkey.h"

GetKey::GetKey(QWidget *parent) : QWidget(parent), ui(new Ui::GetKey){

    explain = new QLabel(this);
    explain->setText("Paste A Public Key To Add Channel To System");
    explain->setGeometry(QRect( QPoint( 20, 5), QSize( 320, 30)));

    input = new QTextEdit( "", this);
    input->setGeometry(QRect( QPoint( 10, 30), QSize( 370, 30)));

    okay_button = new QPushButton( "Add To System", this);
    okay_button->setGeometry(QRect( QPoint( 270, 65), QSize( 110, 30)));

    connect( okay_button, SIGNAL (released()),this, SLOT (parseText()));
}

void GetKey::parseText(){

    QString text = input->toPlainText();

    if(text != ""){

        //seperate key from text
        channel_name = input->toPlainText().mid( 0, text.indexOf("-"));
        QString b64 = text.mid( text.indexOf("-")+1, 44);
        QByteArray test = QByteArray::fromBase64(b64.toStdString().c_str());

        //text from base64 to something that can be converted to unsigned char
        memcpy( publickey, test.toStdString().c_str(), 32);
    }

    sendkey = true;
}

GetKey::~GetKey(){

    delete ui;
}


