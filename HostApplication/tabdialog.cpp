#include "tabdialog.h"
#include "ui_tabdialog.h"

TabDialog::TabDialog( const QString &fileName, QWidget *parent) :QDialog(parent),ui(new Ui::TabDialog){

    ui->setupUi(this);

    QFileInfo fileInfo(fileName);
    tabWidget = new QTabWidget;
    tabWidget->addTab(new GeneralTab(fileInfo), tr("General"));
}

TabDialog::~TabDialog(){

    delete ui;
}
