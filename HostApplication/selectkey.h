#ifndef SELECTKEY_H
#define SELECTKEY_H

#include <QDialog>
#include <QComboBox>
#include <QPushButton>
#include <QDebug>
#include <QLabel>

namespace Ui {

class SelectKey;
}

class SelectKey : public QWidget{

    Q_OBJECT

public:

    explicit SelectKey(QWidget *parent = 0);

    //combobox will contain channel names to select from
    QComboBox *combobox;

    //loads key to clipboard
    QPushButton *clipboard_button;

    //stores clipboard selection for operations in main window
    QString selection;

    bool requestkey = false;

    void updateComboBox(QString);

    ~SelectKey();
public slots:

    void setSelection();

private:

    Ui::SelectKey *ui;
    QLabel *explain;
};

#endif // SELECTKEY_H
