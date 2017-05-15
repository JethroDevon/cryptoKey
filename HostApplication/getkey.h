#ifndef GETKEY_H
#define GETKEY_H

#include <QDialog>
#include <QTextEdit>
#include <QPushButton>
#include <QDebug>
#include <QLabel>

namespace Ui {
class GetKey;
}

class GetKey : public QWidget{

    Q_OBJECT
public:


    QTextEdit *input;
    QPushButton *okay_button;
    bool sendkey = false;

    //stores the recieved key and name for being sent to dongle
    unsigned char publickey[32];
    QString channel_name;

     GetKey(QWidget *parent = 0);
    ~GetKey();

public slots:

     void parseText();

private:

    Ui::GetKey *ui;
    QLabel *explain;
};

#endif // GETKEY_H
