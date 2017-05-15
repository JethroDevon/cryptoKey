#ifndef ADDCONTACT_H
#define ADDCONTACT_H

#include <QDialog>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QDebug>

namespace Ui {

    class AddContact;
}

class AddContact : public QWidget{
    Q_OBJECT

public:

    explicit AddContact(QWidget *parent = 0);

    bool addingkey = false;
    QPushButton *add_button;
    QTextEdit *namefield;
    QString contactname;

    ~AddContact();

public slots:

    void setContact();

private:

    Ui::AddContact *ui;
    QLabel *explain;
};

#endif // ADDCONTACT_H
