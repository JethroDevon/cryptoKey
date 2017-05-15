#include "selectkey.h"
#include "ui_selectkey.h"

SelectKey::SelectKey(QWidget *parent) : QWidget(parent),ui(new Ui::SelectKey){


    clipboard_button = new QPushButton( "Select", this);
    clipboard_button->setGeometry(QRect( QPoint( 10, 65), QSize( 70, 30)));

    combobox = new QComboBox(this);
    combobox->setGeometry(QRect( QPoint( 90, 65), QSize( 200, 30)));

    connect( clipboard_button, SIGNAL (released()),this, SLOT (setSelection()));

    explain = new QLabel( "Select a public key from the connected device. Once\ndownloaded, the public key will be copied to the clipboard\n buffer and console output window.", this);
    explain->setGeometry(QRect( QPoint( 10, 0), QSize( 370, 60)));
}

SelectKey::~SelectKey(){

    delete ui;
}

void SelectKey::updateComboBox(QString item){

    //clear and update whole list
    combobox->addItem(item);
}

void SelectKey::setSelection(){

    selection = combobox->currentText();
    requestkey = true;
}

