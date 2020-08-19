#include <QtWidgets>
#include <QTableWidget>

#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QtCharts/QAbstractBarSeries>
#include <QtCharts/QPercentBarSeries>
#include <QtCharts/QStackedBarSeries>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QLineSeries>
#include <QtCharts/QSplineSeries>
#include <QtCharts/QScatterSeries>
#include <QtCharts/QAreaSeries>
#include <QtCharts/QLegend>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtCore/QRandomGenerator>
#include <QtCharts/QBarCategoryAxis>
#include <QtWidgets/QApplication>
#include <QtCharts/QValueAxis>


#include "commons.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "mainwindow.h"
#include "stat_form.h"


StatForm::StatForm(QWidget *parent) :
    QWidget(parent)
{
    setupUi(this);
    stat_table_ = NULL;
    simple_view_ = NULL;
    bar_view_ = NULL;

    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(updateStat()));

    connect( mDayRadio, SIGNAL(clicked()), this, SLOT(clickDay()));
    connect( mMonthRadio, SIGNAL(clicked()), this, SLOT(clickMonth()));
    connect( mYearRadio, SIGNAL(clicked()), this, SLOT(clickYear()));
}

StatForm::~StatForm()
{

}

void StatForm::initialize()
{
    clickDay();
    updateStat();
}

void StatForm::showEvent(QShowEvent *event)
{
    initialize();
}

void StatForm::clickDay()
{
    time_t now_t = time(NULL);

    QDateTime startTime;
    startTime.setTime_t( now_t - 86400 * 6 );

    QDateTime endTime;
    endTime.setTime_t( now_t );

    mStartDate->setDate( startTime.date() );
    mEndDate->setDate( endTime.date() );

    QString strFormat = "yyyy-MM-dd";

    mStartDate->setDisplayFormat( strFormat );
    mEndDate->setDisplayFormat( strFormat );
}

void StatForm::clickMonth()
{
    int nYear = 0;
    int nMonth = 0;
    int nDay = 1;

    time_t now_t = time(NULL);

    QDateTime dateTime;
    dateTime.setTime_t( now_t );

    QDate endDate = dateTime.date();
    nYear = endDate.year();
    nMonth = endDate.month();

    QDate startDate = endDate.addMonths(-1);

    mStartDate->setDate( startDate );
    mEndDate->setDate( endDate );

    QString strFormat = "yyyy-MM";

    mStartDate->setDisplayFormat( strFormat );
    mEndDate->setDisplayFormat( strFormat );
}

void StatForm::clickYear()
{
    int nYear = 0;
    int nMonth = 1;
    int nDay = 1;

    time_t now_t = time(NULL);

    QDateTime dateTime;
    dateTime.setTime_t( now_t );

    QDate date = dateTime.date();
    nYear = date.year();

    QDate endDate;
    endDate.setDate( nYear, nMonth, nDay );

    QDate startDate = endDate.addYears(-1);

    mStartDate->setDate( startDate );
    mEndDate->setDate( endDate );

    QString strFormat = "yyyy";

    mStartDate->setDisplayFormat( strFormat );
    mEndDate->setDisplayFormat( strFormat );
}

void StatForm::getData()
{
    int nCount = 0;
    QList<int> startList;
    QList<int> endList;

    time_t end_t = mEndDate->dateTime().toTime_t();
    time_t start_t = mStartDate->dateTime().toTime_t();
    time_t diff_t = end_t - start_t;


    unit_list_.clear();
    cert_val_list_.clear();
    revoke_val_list_.clear();
    user_val_list_.clear();
    keypair_val_list_.clear();
    req_val_list_.clear();

    if( mDayRadio->isChecked() )
    {
        nCount = (int)(diff_t / 86400) + 1;
        qDebug( "Count: %d EndDate: %s StartDate: %s",
                nCount,
                mEndDate->dateTime().toString().toStdString().c_str(),
                mStartDate->dateTime().toString().toStdString().c_str() );

        time_t pos_t = start_t;

        for( int i = 0; i < nCount; i++ )
        {
            QDateTime dateTime;
            dateTime.setTime_t( pos_t );
            QString strDate = dateTime.toString( "MM-dd" );

            unit_list_ << strDate;
            startList << pos_t;
            endList << pos_t + 86400 - 1;

            pos_t += 86400;
        }
    }
    else if( mMonthRadio->isChecked() )
    {
        QDate startDate = mStartDate->date();
        QDate endDate = mEndDate->date();
        QDate posDate = startDate;

        for( ; posDate <= endDate; )
        {
            nCount++;
            QDateTime dateTime;
            dateTime.setDate( posDate );

            unit_list_ << dateTime.toString( "yy-MM" );

            startList << dateTime.toTime_t();

            QDate tmpDate = posDate.addMonths(1);
            dateTime.setDate( tmpDate );
            endList << dateTime.toTime_t() - 1;
            posDate = tmpDate;
        }
    }
    else if( mYearRadio->isChecked() )
    {
        QDate startDate = mStartDate->date();
        QDate endDate = mEndDate->date();
        QDate posDate = startDate;

        for( ; posDate <= endDate; )
        {
            nCount++;
            QDateTime dateTime;
            dateTime.setDate( posDate );

            unit_list_ << dateTime.toString( "yyyy" );

            startList << dateTime.toTime_t();

            QDate tmpDate = posDate.addYears(1);
            dateTime.setDate( tmpDate );
            endList << dateTime.toTime_t() - 1;
            posDate = tmpDate;
        }
    }

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();

    for( int i = 0; i < nCount; i++ )
    {
        int nStart = startList.at(i);
        int nEnd = endList.at(i);

        int nCertCnt = dbMgr->getStatisticsCount( nStart, nEnd, "TB_CERT" );
        cert_val_list_.append(nCertCnt);

        int nRevokeCnt = dbMgr->getStatisticsCount( nStart, nEnd, "TB_REVOKED" );
        revoke_val_list_.append( nRevokeCnt );

        int nUserCnt = dbMgr->getStatisticsCount( nStart, nEnd, "TB_USER" );
        user_val_list_.append(nUserCnt);

        int nKeyPairCnt = dbMgr->getStatisticsCount( nStart, nEnd, "TB_KEY_PAIR" );
        keypair_val_list_.append( nKeyPairCnt );

        int nReqCnt = dbMgr->getStatisticsCount( nStart, nEnd, "TB_REQ" );
        req_val_list_.append(nReqCnt);
    }
/*
    cert_val_list_ << 1 << 2 << 3 << 4 << 5 << 6 << 7;
    revoke_val_list_ << 5 << 0 << 0 << 4 << 0 << 7 << 7;
    user_val_list_ << 3 << 5 << 8 << 13 << 8 << 5 << 7;
    keypair_val_list_ << 5 << 6 << 7 << 3 << 4 << 5 << 7;
    req_val_list_ << 9 << 7 << 5 << 3 << 1 << 2 << 7;

    unit_list_ << "Jan" << "Feb" << "Mar" << "Apr" << "May" << "Jun" << "Jul";
    */
}
void StatForm::updateStat()
{
    getData();

    if( simple_view_ )
    {
        mGridLayout->removeWidget( simple_view_ );
        delete simple_view_;
    }

    simple_view_ = new QChartView(createSimpleBarChart());
    mGridLayout->addWidget( simple_view_, 1, 0, 1, 2 );


    if( stat_table_ )
    {
        mGridLayout->removeWidget( stat_table_ );
        delete stat_table_;
    }

    stat_table_ = createSimpleBarTable();
    mGridLayout->addWidget( stat_table_, 2, 0 );

    if( bar_view_ )
    {
        mGridLayout->removeWidget( bar_view_ );
        delete bar_view_;
    }

    bar_view_ = new QChartView(createBarChart());
    mGridLayout->addWidget( bar_view_, 2, 1 );

}

QChart *StatForm::createSimpleBarChart() const
{
    //![1]
    QBarSet *set0 = new QBarSet("Cert");
    QBarSet *set1 = new QBarSet("Revoke");
    QBarSet *set2 = new QBarSet("User");
    QBarSet *set3 = new QBarSet("KeyPair");
    QBarSet *set4 = new QBarSet("Request");

    set0->append( cert_val_list_ );
    set1->append( revoke_val_list_ );
    set2->append( user_val_list_ );
    set3->append( keypair_val_list_ );
    set4->append( req_val_list_ );


    //![2]
    QBarSeries *series = new QBarSeries();
    series->append(set0);
    series->append(set1);
    series->append(set2);
    series->append(set3);
    series->append(set4);

    //![2]

    //![3]
    QChart *chart = new QChart();
    chart->addSeries(series);
    chart->setTitle("CA Manager Statistics");
    chart->setAnimationOptions(QChart::SeriesAnimations);
    //![3]

    //![4]

    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    axisX->append( unit_list_ );
    chart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);

    QValueAxis *axisY = new QValueAxis();
    axisY->setRange(0,15);
    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);
    //![4]

    //![5]
    chart->legend()->setVisible(true);
    chart->legend()->setAlignment(Qt::AlignBottom);
    //![5]

    //![6]
     return chart;
}

DataTable StatForm::generateRandomData(int listCount, int valueMax, int valueCount) const
{
    DataTable dataTable;

    // generate random data
    for (int i(0); i < listCount; i++) {
        DataList dataList;
        qreal yValue(0);
        for (int j(0); j < valueCount; j++) {
            yValue = yValue + QRandomGenerator::global()->bounded(valueMax / (qreal) valueCount);
            QPointF value((j + QRandomGenerator::global()->generateDouble()) * ((qreal) valueMax / (qreal) valueCount),
                          yValue);
            QString label = "Slice " + QString::number(i) + ":" + QString::number(j);
            dataList << Data(value, label);
        }
        dataTable << dataList;
    }

    return dataTable;
}

QChart *StatForm::createBarChart() const
{
    QChart *chart = new QChart();
    chart->setTitle("Certificate and Revoke");

    int nValueMax = cert_val_list_.size();
    QStackedBarSeries *series = new QStackedBarSeries(chart);
    QBarSet *set0 = new QBarSet("Cert");
    QBarSet *set1 = new QBarSet("Revoke");


    QList<qreal> minus_revoke_val_list;

    for( int i = 0; i < revoke_val_list_.size(); i++ )
    {
        minus_revoke_val_list << -revoke_val_list_.at(i);
    }

    set0->append( cert_val_list_ );
    set1->append( minus_revoke_val_list );

    series->append( set0 );
    series->append( set1 );

    chart->addSeries(series);


    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    axisX->append( unit_list_ );
//    axisX->setTitleText("Month");
    chart->addAxis(axisX, Qt::AlignBottom);
    QValueAxis *axisY = new QValueAxis();
    axisY->setRange( -15, 15 );
//    axisY->setTitleText("Count");
    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisX);
    series->attachAxis(axisY);
//![4]

//![5]
    chart->legend()->setVisible(true);
    chart->legend()->setAlignment(Qt::AlignBottom);


    return chart;
}


QTableWidget *StatForm::createSimpleBarTable() const
{
    int i = 0;
    int sum = 0;
    QTableWidget *tableWidget = new QTableWidget;
    QStringList unitList = unit_list_;
    unitList << "Sum";
    QStringList nameList = { "Cert", "Revoke", "User", "KeyPair", "Request" };

    tableWidget->horizontalHeader()->setStretchLastSection(true);

    QString style = "QHeaderView::section {background-color:#808080;color:#FFFFFF;}";
    tableWidget->horizontalHeader()->setStyleSheet( style );
    tableWidget->verticalHeader()->setStyleSheet( style );


    tableWidget->setColumnCount( nameList.size() );
    tableWidget->setHorizontalHeaderLabels( nameList );
 //   tableWidget->setVerticalHeaderLabels( nameList );
    tableWidget->setMinimumHeight(270);

    for( i = 0; i < nameList.size(); i++ )
    {
        tableWidget->setColumnWidth( i, 50 );
    }

    for( i = 0; i < cert_val_list_.size(); i++ )
    {
        tableWidget->insertRow(i);
        int num = cert_val_list_.at(i);
        sum += num;

        tableWidget->setItem( i, 0, new QTableWidgetItem(QString("%1").arg(num)));
    }
    tableWidget->insertRow(i);
    tableWidget->setItem( i, 0, new QTableWidgetItem(QString("%1").arg( sum )));

    sum = 0;
    for( i = 0; i < revoke_val_list_.size(); i++ )
    {
        int num = revoke_val_list_.at(i);
        sum += num;
        tableWidget->setItem( i, 1, new QTableWidgetItem(QString("%1").arg( num )));
    }
    tableWidget->setItem( i, 1, new QTableWidgetItem(QString("%1").arg( sum )));

    sum = 0;
    for( i = 0; i < user_val_list_.size(); i++ )
    {
        int num = user_val_list_.at(i);
        sum += num;
        tableWidget->setItem( i, 2, new QTableWidgetItem(QString("%1").arg( num )));
    }
    tableWidget->setItem( i, 2, new QTableWidgetItem(QString("%1").arg( sum )));


    sum = 0;
    for( i = 0; i < keypair_val_list_.size(); i++ )
    {
        int num = keypair_val_list_.at(i);
        sum += num;
        tableWidget->setItem( i, 3, new QTableWidgetItem(QString("%1").arg(num)));
    }
    tableWidget->setItem( i, 3, new QTableWidgetItem(QString("%1").arg( sum )));

    sum = 0;
    for( i = 0; i < req_val_list_.size(); i++ )
    {
        int num = req_val_list_.at(i);
        sum += num;
        tableWidget->setItem( i, 4, new QTableWidgetItem(QString("%1").arg(num)));
    }
    tableWidget->setItem( i, 4, new QTableWidgetItem(QString("%1").arg( sum )));


    tableWidget->setVerticalHeaderLabels( unitList );
    return tableWidget;
}
