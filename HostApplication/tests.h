#ifndef TESTS_H
#define TESTS_H

#include <QDialog>
#include <QDebug>
#include <QComboBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QPushButton>
#include <QDebug>
#include <QTextEdit>
#include <QLabel>
#include <QBitArray>
#include <QByteArrayList>
#include <QPainter>
#include <QImage>
#include <cmath>
#include <QElapsedTimer>
#include <QFile>


namespace Ui {
class Tests;

}

class Tests : public QWidget{

    Q_OBJECT

public:

    explicit Tests(QWidget *parent = 0);

    void updateComboBox(QString);
    void drawPixels(QString);
    void countOnes(QList<QByteArray>);
    void countBytes(QList<QByteArray>);
    void count(QList<QByteArray>, bool);
    void chi5();
    void liveFuzz();
    void resetTests();
    void writeLatexFile(QString);
    double calculateChi( double, double);
    int fuzzTime();
    void updateTimer();
    int ranLength();
    int ranCount();
    QString nextFuzz();   
    unsigned char createByte();


    //convert first argument to secon argument
    void createBitArray(QByteArray, QBitArray&);
    void createByteArray(QBitArray, QByteArray&);

    //if flags true, run specific test
    bool random = false, cca = false, obtained_cipher = false, whitebox = false, fuzz = false;
    bool fuzzdone = false, startedTimer = false, expecting = false;

    //total amount of random numbers to collect, default is 30, length of random number in digits is default 16
    int rancount = 100, ranlength = 16, sinceLastPing = 0, fuzzcount = 0, lastping = 0, fuzzDuration = 30, blackcount = 0;

    //data for chi^2 test for expected and observed distributions of A, B ... E as well as individual chi distributions
    double Aexp = 0, Bexp = 0, Cexp = 0, Dexp = 0, Eexp = 0;
    double Adist = 0, Bdist = 0, Cdist = 0, Ddist = 0, Edist = 0;
    double Achi = 0, Bchi = 0, Cchi = 0, Dchi = 0, Echi = 0;

    //to store time object
    qint64 elapsedTime;

    //will store an array of byte arrays, random numbers and attacked (avalaunched) ciphertext and letters for random test
    QList<QByteArray>rndns;
    QList<QByteArray>avalaunch;
    QList<char>letters;

    //stores strings to format for tex file
    QList<QString>Latex;

    //stores the responces from the dongle and temporarily stores pings, keeps track of recent fuzzes that may have caused
    //the decice to stop responding, live fuzz strings stores possible causes of fuzzes that gave a result
    QList<QByteArray>fuzzResult;
    QList<QString>recentFuzzes;
    QList<QString>liveFuzzStrings;

    //Stores the results of each sent message for white box testing
    QList<QString> whiteboxList;
    QList<QString> whiteboxCommands;

    //will contain an image made out of random numbers
    QImage randomimage;

    //stores original cipher that was recieved with view to make many avalaunched copies
    QByteArray original_cipher;

    //will store the tag for manipulation
    QByteArray TAG;

    //A few GUI component objects
    QPushButton *runtest_button;
    QLabel *explain, *lengthlab, *samplesizelab;
    QComboBox *channelSelect, *fuzztimeSelect, *randlengthSelect, *randSelect;
    QTextEdit *field;
    QElapsedTimer timer;
    QRadioButton *randbunt, *ccabunt, *fuzzbunt, *whitbunt;
    QCheckBox *latexbunt;
    ~Tests();


public slots:

    void runTests();

private:

    Ui::Tests *ui;
};

#endif // TESTS_H
