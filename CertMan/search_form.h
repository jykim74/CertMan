#ifndef SEARCH_FORM_H
#define SEARCH_FORM_H

#include <QWidget>
#include "ui_search_form.h"

namespace Ui {
class SearchForm;
}

class SearchForm : public QWidget, public Ui::SearchForm
{
    Q_OBJECT

public:
    explicit SearchForm(QWidget *parent = nullptr);
    ~SearchForm();

    int curPage() { return cur_page_; };
    int totalCount() { return total_count_; };
    void updatePageLabel();

    void setTotalCount( int nCount );
    void setCurPage( int nPage );
    void setLeftType( int nType );
    void setLeftNum( int nNum );

    QString getCondName();
    QString getInputWord();

public slots:
    void leftPage();
    void leftEndPage();
    void rightPage();
    void rightEndPage();
    void search();

private:
    void setCondCombo();;

private:
    int cur_page_;
    int total_count_;
    int left_num_;
    int left_type_;
};

#endif // SEARCH_FORM_H
