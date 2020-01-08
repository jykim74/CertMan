#include <QGridLayout>

#include "search_menu.h"
#include "mainwindow.h"
#include "man_applet.h"

static QStringList  s_condCertList = { "Page", "SubjectDN", "Serial" };
static QStringList  s_condCRLList = { "Page" };
static QStringList  s_condKeyPairList = { "Page", "Name" };
static QStringList  s_condReqList = { "Page", "Name" };
static QStringList  s_condRevokeList = { "Page", "Serial" };
static QStringList  s_condUserList = { "Page", "Name", "Email", "SSN" };

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

    cond_combo_->addItems( s_condCertList );

    cur_page_ = 0;
    total_count_ = 0;
    list_count_ = 0;
    cur_offset_ = 0;

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
void SearchMenu::setTotalCount( int nCount )
{
    total_count_ = nCount;
}

void SearchMenu::setCurPage( int nPage )
{
   cur_page_ = nPage;
}

void SearchMenu::setListCount( int nCount )
{
    list_count_ = nCount;
}

void SearchMenu::setCurOffset(int nOffset)
{
    cur_offset_ = nOffset;
}

void SearchMenu::updatePageLabel()
{
    QString label = QString( "%1-%2 of %3" ).arg(cur_offset_).arg( list_count_ ).arg( total_count_ );
    page_label_->setText( label );
}

void SearchMenu::setCondCombo(int nType)
{
    cond_combo_->clear();

    if( nType == RightType::TYPE_CERTIFICATE )
        cond_combo_->addItems( s_condCertList );
    else if( nType == RightType::TYPE_KEYPAIR )
        cond_combo_->addItems( s_condKeyPairList );
    else if( nType == RightType::TYPE_REVOKE )
        cond_combo_->addItems( s_condRevokeList );
    else if( nType == RightType::TYPE_REQUEST )
        cond_combo_->addItems( s_condReqList );
    else if( nType == RightType::TYPE_USER )
        cond_combo_->addItems( s_condUserList );
    else if( nType == RightType::TYPE_CRL )
        cond_combo_->addItems( s_condCRLList );
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
