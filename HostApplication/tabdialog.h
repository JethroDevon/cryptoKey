#ifndef TABDIALOG_H
#define TABDIALOG_H

#include <QDialog>
#include <QTabWidget>

namespace Ui {
class TabDialog;
}

class TabDialog : public QDialog
{
    Q_OBJECT

public:

    explicit TabDialog(const QString &fileName, QWidget *parent = 0);
    ~TabDialog();

private:

    QTabWidget *tabWidget;
    QDialogButtonBox *buttonBox;
};

#endif // TABDIALOG_H
