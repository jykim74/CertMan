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


#include "stat_form.h"

const QStringList kUnitList = { "Day", "Week", "Month", "Year" };

StatForm::StatForm(QWidget *parent) :
    QWidget(parent)
{
    setupUi(this);
    initialize();

    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(updateStat()));

    QChartView *simpleView;

    simpleView = new QChartView(createSimpleBarChart());
    mGridLayout->addWidget( simpleView, 1, 0, 1, 2 );

    QChartView *barView = new QChartView(createBarChart());
    mGridLayout->addWidget( barView, 2, 0 );

    QTableWidget *table = createSimpleBarTable();
    mGridLayout->addWidget( table, 2, 1 );
}

StatForm::~StatForm()
{

}

void StatForm::initialize()
{
    time_t now_t = time(NULL);
    mUnitCombo->addItems( kUnitList );

    QDateTime startTime;
    startTime.setTime_t( now_t - 86400 * 7 );

    QDateTime endTime;
    endTime.setTime_t( now_t );

    mStartDate->setDate( startTime.date() );
    mEndDate->setDate( endTime.date() );

    getData();
}

void StatForm::getData()
{
    cert_val_list_ << 1 << 2 << 3 << 4 << 5 << 6;
    revoke_val_list_ << 5 << 0 << 0 << 4 << 0 << 7;
    user_val_list_ << 3 << 5 << 8 << 13 << 8 << 5;
    keypair_val_list_ << 5 << 6 << 7 << 3 << 4 << 5;
    req_val_list_ << 9 << 7 << 5 << 3 << 1 << 2;
}
void StatForm::updateStat()
{

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
    QStringList categories;
    categories << "Jan" << "Feb" << "Mar" << "Apr" << "May" << "Jun";
    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    axisX->append(categories);
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
    chart->setTitle("CA Manager Cert and Revoke");

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

    QStringList categories = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul"
    };

    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    axisX->append(categories);
    axisX->setTitleText("Month");
    chart->addAxis(axisX, Qt::AlignBottom);
    QValueAxis *axisY = new QValueAxis();
    axisY->setRange( -15, 15 );
    axisY->setTitleText("Count");
    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisX);
    series->attachAxis(axisY);
//![4]

//![5]
    chart->legend()->setVisible(true);
    chart->legend()->setAlignment(Qt::AlignBottom);

    /*
    chart->createDefaultAxes();
    chart->axes(Qt::Vertical).first()->setRange(0, nValueMax * 2);
    // Add space to label to add space between labels and axis
    QValueAxis *axisY = qobject_cast<QValueAxis*>(chart->axes(Qt::Vertical).first());
    Q_ASSERT(axisY);
    axisY->setLabelFormat("%.1f  ");
    */

    return chart;
}


QTableWidget *StatForm::createSimpleBarTable() const
{
    QTableWidget *tableWidget = new QTableWidget;
    QStringList headerList = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Sum" };
    QStringList nameList = { "Cert", "Revoke", "User", "KeyPair", "Request" };

    tableWidget->horizontalHeader()->setStretchLastSection(true);


    tableWidget->setColumnCount( headerList.size() );
    tableWidget->setHorizontalHeaderLabels( headerList );
    tableWidget->setVerticalHeaderLabels( nameList );

    for( int i = 0; i < headerList.size(); i++ )
    {
        tableWidget->setColumnWidth( i, 20 );
    }

    tableWidget->insertRow(0);

    for( int i = 0; i < cert_val_list_.size(); i++ )
    {
        tableWidget->setItem( 0, i, new QTableWidgetItem(QString("%1").arg(cert_val_list_.at(i))));
    }

    tableWidget->insertRow(1);

    for( int i = 0; i < revoke_val_list_.size(); i++ )
    {
        tableWidget->setItem( 1, i, new QTableWidgetItem(QString("%1").arg(revoke_val_list_.at(i))));
    }

    tableWidget->insertRow(2);

    for( int i = 0; i < user_val_list_.size(); i++ )
    {
        tableWidget->setItem( 2, i, new QTableWidgetItem(QString("%1").arg(user_val_list_.at(i))));
    }

    tableWidget->insertRow(3);

    for( int i = 0; i < keypair_val_list_.size(); i++ )
    {
        tableWidget->setItem( 3, i, new QTableWidgetItem(QString("%1").arg(keypair_val_list_.at(i))));
    }

    tableWidget->insertRow(4);

    for( int i = 0; i < req_val_list_.size(); i++ )
    {
        tableWidget->setItem( 4, i, new QTableWidgetItem(QString("%1").arg(req_val_list_.at(i))));
    }

    return tableWidget;
}
