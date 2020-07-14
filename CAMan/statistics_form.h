#ifndef STATISTICS_FORM_H
#define STATISTICS_FORM_H

#include <QWidget>
#include <QtCharts/QChartGlobal>
#include "ui_statistics_form.h"

namespace Ui {
class StatisticsForm;
}

#include <QtWidgets/QWidget>


QT_BEGIN_NAMESPACE
class QComboBox;
class QCheckBox;
QT_END_NAMESPACE

QT_CHARTS_BEGIN_NAMESPACE
class QChartView;
class QChart;
QT_CHARTS_END_NAMESPACE

typedef QPair<QPointF, QString> Data;
typedef QList<Data> DataList;
typedef QList<DataList> DataTable;

QT_CHARTS_USE_NAMESPACE

class StatisticsForm : public QWidget, public Ui::StatisticsForm
{
    Q_OBJECT

public:
    explicit StatisticsForm(QWidget *parent = nullptr);
    ~StatisticsForm();
private Q_SLOTS:
    void updateUI();

private:
    DataTable generateRandomData(int listCount, int valueMax, int valueCount) const;
    void populateThemeBox();
    void populateAnimationBox();
    void populateLegendBox();
    void connectSignals();
    QChart *createAreaChart() const;
    QChart *createBarChart(int valueCount) const;
    QChart *createPieChart() const;
    QChart *createLineChart() const;
    QChart *createSplineChart() const;
    QChart *createScatterChart() const;

private:
    int m_listCount;
    int m_valueMax;
    int m_valueCount;
    QList<QChartView *> m_charts;
    DataTable m_dataTable;

};

#endif // STATISTICS_FORM_H
