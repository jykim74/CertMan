/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QRegExpValidator>

#include "search_form.h"
#include "commons.h"
#include "man_tree_item.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "settings_mgr.h"

static QStringList  s_condBaseList = { "Page" };
static QStringList  s_condCertList = { "Page", "SubjectDN", "Serial" };
static QStringList  s_condCRLList = { "Page" };
static QStringList  s_condKeyPairList = { "Page", "Name" };
static QStringList  s_condReqList = { "Page", "Name" };
static QStringList  s_condRevokeList = { "Page", "Serial" };
static QStringList  s_condUserList = { "Page", "Name", "Email", "SSN" };

SearchForm::SearchForm(QWidget *parent) :
    QWidget(parent)
{
    setupUi(this);

    mCondCombo->addItems( s_condCertList );

    cur_page_ = 0;
    total_count_ = 0;
    left_type_ = -1;
    left_num_ = -1;

    connect( mLeftEndBtn, SIGNAL(clicked()), this, SLOT(leftEndPage()));
    connect( mLeftBtn, SIGNAL(clicked()), this, SLOT(leftPage()));
    connect( mRightEndBtn, SIGNAL(clicked()), this, SLOT(rightEndPage()));
    connect( mRightBtn, SIGNAL(clicked()), this, SLOT(rightPage()));
    connect( mSearchBtn, SIGNAL(clicked()), this, SLOT(search()));
    connect( mCondCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCond(int)));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mLeftEndBtn->setFixedWidth(40);
    mRightEndBtn->setFixedWidth(40);
#endif
    changeCond(0);
    resize(width(), minimumSizeHint().height());
}

SearchForm::~SearchForm()
{

}

void SearchForm::setTotalCount( int nCount )
{
    total_count_ = nCount;
}

void SearchForm::setCurPage( int nPage )
{
   cur_page_ = nPage;
}


void SearchForm::setLeftType( int nType )
{
    left_type_ = nType;
    setCondCombo();
}

void SearchForm::setLeftNum( int nNum )
{
    left_num_ = nNum;
}

void SearchForm::updatePageLabel()
{
    int nOffset = cur_page_ * manApplet->settingsMgr()->listCount();
    int nEnd = 0;

    nEnd = nOffset + manApplet->mainWindow()->rightCount();
    if( nEnd > 0 ) nOffset += 1;

    QString label = QString( "%1-%2 of %3 [%4p]" )
            .arg( nOffset )
            .arg( nEnd )
            .arg( total_count_ )
            .arg(cur_page_ + 1);

    mPageLabel->setText( label );
}

void SearchForm::setCondCombo()
{
    mCondCombo->clear();
    mInputText->clear();

    if( left_type_ == CM_ITEM_TYPE_ROOTCA
            || left_type_ == CM_ITEM_TYPE_IMPORT_CERT
            || left_type_ == CM_ITEM_TYPE_CA
            || left_type_ == CM_ITEM_TYPE_CERT
            || left_type_ == CM_ITEM_TYPE_SUBCA )
        mCondCombo->addItems( s_condCertList );
    else if( left_type_ == CM_ITEM_TYPE_KEYPAIR )
        mCondCombo->addItems( s_condKeyPairList );
    else if( left_type_ == CM_ITEM_TYPE_REVOKE )
        mCondCombo->addItems( s_condRevokeList );
    else if( left_type_ == CM_ITEM_TYPE_REQUEST )
        mCondCombo->addItems( s_condReqList );
    else if( left_type_ == CM_ITEM_TYPE_USER  )
        mCondCombo->addItems( s_condUserList );
    else if( left_type_ == CM_ITEM_TYPE_CRL
             || left_type_ == CM_ITEM_TYPE_IMPORT_CRL )
        mCondCombo->addItems( s_condCRLList );
    else
        mCondCombo->addItems( s_condBaseList );
}

QString SearchForm::getCondName()
{
    return mCondCombo->currentText();
}

QString SearchForm::getInputWord()
{
    return mInputText->text();
}

void SearchForm::leftPage()
{
    cur_page_ = cur_page_ - 1;
    if( cur_page_ < 0 ) cur_page_ = 0;

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchForm::leftEndPage()
{
    cur_page_ = 0;

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchForm::rightPage()
{
    int nListCnt = manApplet->settingsMgr()->listCount();
    int end_page = int ( (total_count_ - 1 ) / nListCnt );

    cur_page_ = cur_page_ + 1;
    if( cur_page_ >= end_page ) cur_page_ = end_page;

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchForm::rightEndPage()
{
    int nListCnt = manApplet->settingsMgr()->listCount();
    int end_page = int ( (total_count_ - 1 ) / nListCnt );
    cur_page_ = end_page;

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchForm::search()
{
    QString strTarget = mCondCombo->currentText();
    QString strWord = mInputText->text();

    if( manApplet->dbMgr()->isOpen() == false )
    {
        manApplet->warningBox( tr( "DB is not connected" ), this );
        return;
    }

    if( strWord.length() < 1 )
    {
        manApplet->warningBox( tr( "Please enter your search term"), this);
        mInputText->setFocus();
        return;
    }

    if( strTarget == "Page" )
    {
        cur_page_ = strWord.toInt();
        cur_page_--;
        if( cur_page_ < 0 ) cur_page_ = 0;
        mInputText->clear();
    }

    manApplet->mainWindow()->createRightList( left_type_, left_num_ );
}

void SearchForm::changeCond( int index )
{
    QString strCond = mCondCombo->currentText().toUpper();

    if( strCond == "PAGE" )
    {
        QRegExp regExp("^[0-9-]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );

        mInputText->setValidator( regVal );
        mInputText->setPlaceholderText( tr( "[0-9]*" ));
    }
    else if( strCond == "SERIAL" )
    {
        QRegExp regExp("^[0-9a-fA-F]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );

        mInputText->setValidator( regVal );
        mInputText->setPlaceholderText( tr( "[A-Za-f0-9]*" ));
    }
    else
    {
        mInputText->setValidator( nullptr );
        mInputText->setPlaceholderText( tr("String value" ));
    }
}
