#include <QGridLayout>

#include "search_menu.h"
#include "mainwindow.h"
#include "man_applet.h"

static QStringList  s_condList = { "Name", "Page" };

SearchMenu::SearchMenu(QWidget *parent) : QWidget(parent)
{
    page_label_ = new QLabel( tr("0-0 of 0") );
    left_end_btn_ = new QPushButton( tr("<<"));
    left_btn_ = new QPushButton( tr( "<" ));
    right_end_btn_ = new QPushButton( tr(">>"));
    right_btn_ = new QPushButton( tr( ">"));
    cond_combo_ = new QComboBox;
    input_text_ = new QLineEdit;
    search_btn_ = new QPushButton( tr( "Search"));

    cond_combo_->addItems( s_condList );

    cur_page_ = 0;
    total_count_ = 0;

    connect( left_end_btn_, SIGNAL(clicked()), this, SLOT(leftEndPage()));
    connect( left_btn_, SIGNAL(clicked()), this, SLOT(leftPage()));
    connect( right_end_btn_, SIGNAL(clicked()), this, SLOT(rightEndPage()));
    connect( right_btn_, SIGNAL(clicked()), this, SLOT(rightPage()));
    connect( search_btn_, SIGNAL(clicked()), this, SLOT(search()));

    setupModel();
}

void SearchMenu::setupModel()
{
    QGridLayout *layout = new QGridLayout();

    layout->addWidget( left_end_btn_, 0, 0 );
    layout->addWidget( left_btn_, 0, 1 );
    layout->addWidget( page_label_, 0, 2 );
    layout->addWidget( right_btn_, 0, 3 );
    layout->addWidget( right_end_btn_, 0, 4 );
    layout->addWidget( cond_combo_, 0, 5 );
    layout->addWidget( input_text_, 0, 6 );
    layout->addWidget( search_btn_, 0, 7 );

    setLayout( layout );
}

void SearchMenu::leftPage()
{

}

void SearchMenu::leftEndPage()
{

}

void SearchMenu::rightPage()
{

}

void SearchMenu::rightEndPage()
{

}

void SearchMenu::search()
{

}
