#ifndef SEARCHMENU_H
#define SEARCHMENU_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>

class SearchMenu : public QWidget
{
    Q_OBJECT
public:
    explicit SearchMenu(QWidget *parent = nullptr);
    int curPage() { return cur_page_; };
    int totalCount() { return total_count_; };
    int listCount() { return list_count_; };
    int curOffset() { return cur_offset_; };
    void updatePageLabel();
    void setCondCombo( int nType );

    void setTotalCount( int nCount );
    void setCurPage( int nPage );
    void setListCount( int nCount );
    void setCurOffset( int nOffset );

    QString getCondName();
    QString getInputWord();


private:
    void setupModel();

signals:

public slots:
    void leftPage();
    void leftEndPage();
    void rightPage();
    void rightEndPage();
    void search();


private:
    QLabel          *page_label_;
    QPushButton     *left_end_btn_;
    QPushButton     *left_btn_;
    QPushButton     *right_end_btn_;
    QPushButton     *right_btn_;
    QComboBox       *cond_combo_;
    QLineEdit       *input_text_;
    QPushButton     *search_btn_;

    int             cur_page_;
    int             list_count_;
    int             total_count_;
    int             cur_offset_;
};

#endif // SEARCHMENU_H
