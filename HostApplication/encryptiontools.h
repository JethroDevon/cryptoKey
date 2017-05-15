#ifndef ENCRYPTIONTOOLS_H
#define ENCRYPTIONTOOLS_H

#include <QFile>
#include <QFileDialog>
#include <QString>
#include <QByteArray>
#include <QDialog>
#include <QComboBox>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QDebug>
#include <QDir>
#include <QIODevice>
#include "addcontact.h"
#include "selectkey.h"
#include "getkey.h"


namespace Ui {

    class EncryptionTools;


}

class EncryptionTools : public QWidget{


    Q_OBJECT

public:


    void updateComboBox(QString);
    bool encrypting = false, decrypting = false, wait = false;
    QPushButton *encrypt_button, *decrypt_button;

    //channel selection
    QString selection;
    QUrl url;

    //gui objects

    QLabel *explain;
    QComboBox *channelSelect;
    QTextEdit *field;
    QTabWidget *tb;

    //this array will store the file
    QByteArray filebytes;
    unsigned long long filesize = 0;

    AddContact AC;
    SelectKey SK;
    GetKey GK;

    explicit EncryptionTools(QWidget *parent = 0);
    ~EncryptionTools();

public slots:

    void encrypt();
    void decrypt();

signals:




private:

    Ui::EncryptionTools *ui;

#include "getkey.h"
};

#endif // ENCRYPTIONTOOLS_H
