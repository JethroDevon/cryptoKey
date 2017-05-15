#ifndef PASSMAN_H
#define PASSMAN_H

#include <QWidget>

namespace Ui {

    class PassMan;
}

class PassMan : public QWidget{
    Q_OBJECT

public:

    explicit PassMan(QWidget *parent = 0);
    ~PassMan();

private:

    Ui::PassMan *ui;
};

#endif // PASSMAN_H
