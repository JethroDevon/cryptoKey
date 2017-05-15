#include "addcontact.h"
#include "ui_addcontact.h"

AddContact::AddContact(QWidget *parent) : QWidget(parent), ui(new Ui::AddContact){

    add_button = new QPushButton( "Save", this);
    add_button->setGeometry(QRect( QPoint( 100, 65), QSize( 130,30)));

    namefield = new QTextEdit( "", this);
    namefield->setGeometry(QRect( QPoint( 10, 65), QSize( 80, 30)));

    explain = new QLabel( "Entering an eight digit name for a secure channel and then\npressing 'Save' will store new public key with\nthat channels name on the connected device.", this);
    explain->setGeometry(QRect( QPoint( 10, 0), QSize( 370, 60)));

    connect( add_button, SIGNAL (released()),this, SLOT (setContact()));
}

AddContact::~AddContact(){

    delete ui;
}

void AddContact::setContact(){

    contactname = namefield->toPlainText();

    if( contactname != ""){

        addingkey = true;
    }else{

        addingkey = false;
    }
}
