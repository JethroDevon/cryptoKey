#include "tests.h"
#include "ui_tests.h"

Tests::Tests(QWidget *parent) : QWidget(parent), ui(new Ui::Tests){

    explain = new QLabel( "SELECT A TEST, SET OPTIONS THEN PRESS 'RUN TEST'", this);
    explain->setGeometry(QRect( QPoint( 35, 0), QSize( 370, 30)));

    channelSelect = new QComboBox(this);
    channelSelect->setGeometry(QRect( QPoint( 10, 40), QSize( 200, 30)));

    runtest_button = new QPushButton( "Run Tests", this);
    runtest_button->setGeometry(QRect( QPoint( 325, 260), QSize( 70, 30)));

    //editable text field with default 64 bit long message for seeding tests
    field = new QTextEdit("Test string 123", this);
    field->setGeometry(QRect( QPoint( 10, 80), QSize( 300, 30)));

    randbunt = new QRadioButton( "Chi^2 Random Number Tests", this);
    randbunt->setGeometry(QRect( QPoint( 10, 140), QSize( 220, 30)));

    ccabunt = new QRadioButton( "Test Cryptosystem", this);
    ccabunt->setGeometry(QRect( QPoint( 220, 40), QSize( 190, 30)));

    fuzzbunt = new QRadioButton( "Fuzz Connected Device for ", this);
    fuzzbunt->setGeometry(QRect( QPoint( 10, 220), QSize( 200, 30)));

    whitbunt = new QRadioButton( "Automate White Box Test", this);
    whitbunt->setGeometry(QRect( QPoint( 10, 260), QSize( 190, 30)));

    fuzztimeSelect = new QComboBox(this);
    fuzztimeSelect->setGeometry(QRect( QPoint( 195, 220), QSize( 100, 30)));

    randSelect = new QComboBox(this);
    randSelect->setGeometry(QRect( QPoint( 90, 165), QSize( 45, 30)));

    randlengthSelect = new QComboBox(this);
    randlengthSelect->setGeometry(QRect( QPoint( 335, 165), QSize( 45, 30)));

    lengthlab = new QLabel( "Length of random numbers", this);
    lengthlab->setGeometry(QRect( QPoint( 165, 165), QSize( 165, 30)));

    samplesizelab = new QLabel( "Sample size", this);
    samplesizelab->setGeometry(QRect( QPoint( 10, 165), QSize( 75, 30)));

    latexbunt = new QCheckBox( "Write to test.tex", this);
    latexbunt->setGeometry(QRect( QPoint( 80, 15), QSize( 280, 30)));

    //set a radio button to true by default
    ccabunt->setChecked(true);

    //ugly method of initialising drop down boxes for random number amounts, random number lengths
    //and time to spend fuzzing
    randSelect->addItem("10");
    randSelect->addItem("30");
    randSelect->addItem("100");
    randSelect->addItem("200");
    randSelect->addItem("1000");
    randSelect->addItem("10000");

    randlengthSelect->addItem("1");
    randlengthSelect->addItem("4");
    randlengthSelect->addItem("8");
    randlengthSelect->addItem("16");
    randlengthSelect->addItem("32");
    randlengthSelect->addItem("64");
    randlengthSelect->addItem("128");

    randSelect->setCurrentIndex(1);
    randlengthSelect->setCurrentIndex(4);

    //add strings to fuzz time selection
    fuzztimeSelect->addItem("10 Seconds");
    fuzztimeSelect->addItem("30 Seconds");
    fuzztimeSelect->addItem("1 minute");
    fuzztimeSelect->addItem("2 minutes");
    fuzztimeSelect->addItem("5 minutes");
    fuzztimeSelect->addItem("10 minutes");
    fuzztimeSelect->addItem("1 hour");
    fuzztimeSelect->addItem("2 hours");
    fuzztimeSelect->addItem("5 hours");

    //following string literals are so as to create a set of commands that
    //should coincide
    whiteboxCommands << "<ping>";
    whiteboxCommands << "<add><test-1234567890qwertyuiopasdfghjklzxcvbnm>";
    whiteboxCommands << "<pop><test>";
    whiteboxCommands << "<ran><4>";
    whiteboxCommands << "<ran><8>";
    whiteboxCommands << "<vrb>";
    whiteboxCommands << "<vrb>";

    connect( runtest_button, SIGNAL (released()),this, SLOT (runTests()));
}

Tests::~Tests(){

    delete ui;
}

void Tests::updateComboBox(QString item){

    //clear and update whole list
    channelSelect->addItem(item);
}

//initialises option variables with user input data and manages logic to collect test data
void Tests::runTests(){

    if(!(fuzz || cca || random || whitebox)){

        fuzz = fuzzbunt->isChecked();
        cca = ccabunt->isChecked();
        random = randbunt->isChecked();
        whitebox = whitbunt->isChecked();
        runtest_button->hide();

        //ammend command in whitebox test
        whiteboxCommands << "<get><" + channelSelect->currentText() + ">";
    }
}

void Tests::resetTests(){

    Aexp = 0; Bexp = 0; Cexp = 0; Dexp = 0; Eexp = 0; Adist = 0; Bdist = 0; Cdist = 0; Ddist = 0; Edist = 0;
    Achi = 0; Bchi = 0; Cchi = 0; Dchi = 0; Echi = 0;

    letters.clear();
}

void Tests::countOnes(QList<QByteArray>bytes){

    count( bytes, false);
}


void Tests::countBytes(QList<QByteArray>bytes){

    count( bytes, true);
}

void Tests::createBitArray( QByteArray bytes, QBitArray &bits){

    //put all bits of allbytes on bit array
    bits.fill(0);
    for(int i = 0; i < bytes.size()-4; i++)
        for(int b = 0; b < 8; b++){

            bits.setBit( i * 8 + b , bytes.at(i)&(1<<(7-b)));
        }
}

void Tests::createByteArray( QBitArray bits, QByteArray &bytes){

    for(int i = 0; i < bits.size()-4; i++)
        for(int b = 0; b < 8; b++){

            bytes[b/8] = (bytes.at(b/8) | ((bits[b]?1:0)<<(7-(b%8))));
        }
}

//initialises an array of letters using die hard 'count the ones' method of collecting an array
//of letters to perform chi^2 analysis on
void Tests::count(QList<QByteArray>bytes, bool mode){

    int counter = 1;
    if(mode){

        counter = 4;
    }

    //put whole list on one array
    QByteArray allbytes;
    for(int x = 0; x < bytes.size(); x++)
        for(int l = 0; l < bytes[x].size(); l++)
            allbytes.append( bytes[x].at(l));

    //put all bits of allbytes on bit array
    QBitArray bits(allbytes.size() * 8);
    createBitArray( allbytes, bits);

    //counts the '1s' for every four overlapping bits and pushes an
    //assiciated char to an array based on the number of bits
    for(int b = 0; b < bits.size()-4; b+=counter){

        int totalbits = 0;

        for(int bitcount = 0; bitcount < 4; bitcount++){

            if(bits[b + bitcount] == 1)
                totalbits++;
        }

        switch (totalbits) {
        case 0:
            letters << 'A';
            Adist++;
            break;
        case 1:
            letters << 'B';
            Bdist++;
            break;
        case 2:
            letters << 'C';
            Cdist++;
            break;
        case 3:
            letters << 'D';
            Ddist++;
            break;
        case 4:
            letters << 'E';
            Edist++;
        }
    }

    //mode will effect what output is written to
    if(mode){

        Latex << "\\subsubsection{Dispersal Of Bytes Using 'Count-the-1s' method} \n";
    }else{

        Latex << "\\subsubsection{Dispersal Of Bits Using 'Count-the-bytes' method} \n";
    }

    chi5();
}

//extracts data from the initialised letters
void Tests::chi5(){

    //now that the letters array has been initialised expected variables are calculated
    Aexp = letters.size()/16; Eexp = letters.size()/16; Bexp = letters.size()/4; Dexp = letters.size()/4;
    Cexp = letters.size()/2.666666666667;

    //work out the chi squared distribution for each
    Achi = calculateChi( Aexp, Adist); Bchi = calculateChi( Bexp, Bdist); Cchi = calculateChi( Cexp, Cdist); Dchi = calculateChi( Dexp, Ddist);
    Echi = calculateChi( Eexp, Edist);

    int chiout = Achi + Bchi + Cchi + Dchi + Echi;

    QString chioutstring = QString::number(chiout);

    //the following block outputs strings of gathhered data to debug window and string array list for creating latex files

    Latex << "\\begin{center} \n";
    Latex << "\\caption{ Chi$^2$ test with " +  QString::number(ranCount()) + " random numbers of " + QString::number(ranLength()) +" figures in length} \n";
    Latex << "\\begin{tabular}{||C||C|C|C|C|C||} \n";
    Latex << "\\hline \n";
    Latex << "& A & B & C & D & E \\\\ \n";
    Latex << "\\hline \n";

    QString ltemp = "Expected & " + QString::number(Aexp) + " & " + QString::number(Bexp) + " & " + QString::number(Cexp) + " & " + QString::number(Dexp) + " & " + QString::number(Eexp) + "\\\\ \n";
    qDebug()<< ltemp;
    Latex << ltemp;
     Latex << "\\hline \n";
    ltemp = "Observed & " + QString::number(Adist) + " & " + QString::number(Bdist) + " & " + QString::number(Cdist) + " & " + QString::number(Ddist) + " & " + QString::number(Edist) + "\\\\ \v";
    qDebug()<< ltemp;
    Latex << ltemp;
    Latex << "\\hline \n";
    ltemp = "(E-O)^2/E & " + QString::number(Achi) + " & " + QString::number(Bchi) + " & " + QString::number(Cchi) + " & " + QString::number(Dchi) + " & " + QString::number(Echi) + "\\\\";
    qDebug()<< ltemp;
    Latex << ltemp;
    Latex << "\\hline \n";
    Latex << "\\end{tabular} \n";
    Latex << "\\end{center} \n";
    qDebug()<<"Chi Square total: " << chioutstring;
    Latex << "Chi$^2$ total: " + chioutstring;

    resetTests();
}

double Tests::calculateChi( double E, double O){

    return pow(E - O, 2)/E;
}

void Tests::liveFuzz(){

    liveFuzzStrings.append(recentFuzzes.back());
    liveFuzzStrings.append(recentFuzzes.back());
    liveFuzzStrings.append(recentFuzzes.back());
    liveFuzzStrings.append(recentFuzzes.back());
}

//initialises qimage object 'randomimage' with black or white pixels depending on whether an assosiated
//bit is a 1 or a 0
void Tests::drawPixels(QString filename){

    //width of a qarraylist in bits and height is total number of arrays on the array list
    int width =  rndns[0].size();
    int height = rndns.size();

    //initialise image object
    randomimage = QImage( width * 8, height, QImage::Format_RGB16);

    qDebug()<< "creating "<< width*8 << " by " << height << "image.";
    uint black = qRgb( 0, 0, 0);
    uint white = qRgb( 255, 255, 255);

    //make sure byte array lists are not empty and if not that the random numbers they contain are greater
    //than length 0
    if( width > 0 && height > 0){

        //loops for each pixel in an image as well as each bit on each random array on the random arraylise
        for(int i = 0; i < height; i++)
                for(int j = 0; j < width; j++){

                    uint8_t ubite =  rndns[i].at(j);

                    for(int b = 0; b < 8; b++){

                        //if specific bit is 1 draw it white else black and then move to next bit or row
                        if(((ubite & (1 << b)) >> b) == 1){

                             randomimage.setPixel( (j*8) + b , i, white);
                        }else{

                             randomimage.setPixel( (j*8) + b, i, black);
                        }
                    }
                }
    }

    randomimage.save(filename + ".bmp");

    Latex << "\\subsubsection{Dispersal Of Random Numbers} ";

    //append display image tex headings
    Latex << "\\begin{figure}[!htpd] \n";
    Latex << "\\includegraphics[scale = 2]{" + filename +".bmp} \n";
    Latex << "\\end{figure} \n";
}

//returns length of random number
int Tests::ranLength(){

    switch (randlengthSelect->currentIndex()) {
    case 0:
        return 1;
    case 1:
        return 4;
    case 2:
        return 8;
    case 3:
        return 16;
    case 4:
        return 32;
    case 5:
        return 64;
    case 6:
        return 128;

    default:

        return 16;
        break;
    }
}

//returns sample size relating to index in combobox
int Tests::ranCount(){

    switch (randSelect->currentIndex()) {
    case 0:
        return 10;
    case 1:
        return 30;
    case 2:
        return 100;
    case 3:
        return 200;
    case 4:
        return 1000;
    case 5:
        return 10000;

    default:

        return 10;
        break;
    }
}

int Tests::fuzzTime(){

    switch (fuzztimeSelect->currentIndex()) {
    case 0:
        return 10;
    case 1:
        return 30;
    case 2:
        return 60;
    case 3:
        return 120;
    case 4:
        return 300;
    case 5:
        return 600;
    case 6:
        return 1200;
    case 7:
        return 3000;

    default:

        return 10;
        break;
    }
}

unsigned char Tests::createByte(){

    unsigned char newbyte = 255;

    //creates a random number of bytes between 1 and 10 and randomly flips bits within it
    for(int x = 0; x < 8; x++){

          newbyte ^= ( rand() %2 << x);
    }

    return newbyte;
}

//creates the next string to put onto the fuzzing array
QString Tests::nextFuzz(){

    fuzzcount++;
    ++lastping;
    QString fuzzblank;
    elapsedTime = timer.nsecsElapsed()/1000000000;

    //keeps track of how many messages it has been since last ping was sent
    //stops fuzz test and displays recent strings that could have caused poor
    //responsivness
    if(lastping > 10){

        return "ping";
    }

    int fuzzlength = rand()%5;

    for(int x = 0; x < fuzzlength; x++)
        fuzzblank.append(createByte());

    //stores the string on recent fuzz array
    recentFuzzes << fuzzblank;

    //removes anything over the twentieth string from recent fuzz array
    recentFuzzes.removeAt(30);

    return fuzzblank;
}

void Tests::updateTimer(){

    //if clock has stoped stop fuzz test and store results
    if( elapsedTime > fuzzTime()){

        fuzzdone = true;
        qDebug()<< "test complete";
    }

    if(lastping > 30){

        qDebug()<<"dongle has become unresponsive during fuzz test";
        fuzz = false;
        fuzzdone = true;
    }
}

void Tests::writeLatexFile(QString filename){

    qDebug()<<"Creating Latex Document";
    QFile file( filename + ".tex");
    if( file.open(QIODevice::ReadWrite)){

         QTextStream out(&file);
         for(int x = 0; x < Latex.size(); x++){

             out << Latex.at(x);
         }
    }

    Latex.clear();
}

