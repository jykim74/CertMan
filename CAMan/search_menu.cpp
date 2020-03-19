#include <QGridLayout>

#include "commons.h"
#include "man_tree_item.h"
#include "search_menu.h"
#include "mainwindow.h"
#include "man_applet.h"

static QStringList  s_condBaseList = { "Page" };
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
    left_type_ = -1;
    left_num_ = -1;

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


void SearchMenu::setLeftType( int nType )
{
    left_type_ = nType;
    setCondCombo();
}

void SearchMenu::setLeftNum( int nNum )
{
    left_num_ = nNum;
}

void SearchMenu::updatePageLabel()
{
    int nOffset = cur_page_ * kListCount;
    int nEnd = nOffset + manApplet->mainWindow()->rightCount();

    QString label = QString( "%1-%2 of %3 [%4p]" ).arg( nOffset + 1 ).arg( nEnd ).arg( total_count_ ).arg(cur_page_+1);
    page_label_->setText( label );
}

void SearchMenu::setCondCombo()
{
    cond_combo_->clear();
    input_text_->clear();

    if( left_type_ == CM_ITEM_TYPE_ROOTCA
            || left_type_ == CM_ITEM_TYPE_IMPORT_CERT
            || left_type_ == CM_ITEM_TYPE_CA
            || left_type_ == CM_ITEM_TYPE_CERT
            || left_type_ == CM_ITEM_TYPE_SUBCA )
        cond_combo_->addItems( s_condCertList );
    else if( left_type_ == CM_ITEM_TYPE_KEYPAIR )
        cond_combo_->addItems( s_condKeyPairList );
    else if( left_type_ == CM_ITEM_TYPE_REVOKE )
        cond_combo_->addItems( s_condRevokeList );
    else if( left_type_ == CM_ITEM_TYPE_REQUEST )
        cond_combo_->addItems( s_condReqList );
    else if( left_type_ == CM_ITEM_TYPE_USER  )
        cond_combo_->addItems( s_condUserList );
    else if( left_type_ == CM_ITEM_TYPE_CRL
             || left_type_ == CM_ITEM_TYPE_IMPORT_CRL )
        cond_combo_->addItems( s_condCRLList );
    else
        cond_combo_->addItems( s_condBaseList );
}

QString SearchMenu::getCondName()
{
    return cond_combo_->currentText();
}

QString SearchMenu::getInputWord()
{
    return input_text_->text();
}

void SearchMenu::leftPage()
{
    cur_page_ = cur_page_ - 1;
    if( cur_page_ < 0 ) cur_page_ = 0;

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchMenu::leftEndPage()
{
    cur_page_ = 0;
    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchMenu::rightPage()
{
    int end_page = int ( (total_count_ - 1 ) / kListCount );

    cur_page_ = cur_page_ + 1;
    if( cur_page_ >= end_page ) cur_page_ = end_page;

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchMenu::rightEndPage()
{
    int end_page = int ( (total_count_ - 1 ) / kListCount );
    cur_page_ = end_page;
    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchMenu::search()
{
    QString strTarget = cond_combo_->currentText();
    QString strWord = input_text_->text();

    if( strTarget == "Page" )
    {
        cur_page_ = strWord.toInt();
        input_text_->clear();
    }

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}
