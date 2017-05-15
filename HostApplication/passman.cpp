#include "passman.h"
#include "ui_passman.h"

PassMan::PassMan(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PassMan)
{
    ui->setupUi(this);
}

PassMan::~PassMan()
{
    delete ui;
}
