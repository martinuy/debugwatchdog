#-------------------------------------------------
#
# Project created by QtCreator 2017-11-07T12:35:19
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = debugwatchdogui
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui

unix:!macx: LIBS += -L$$PWD/../../lib/ -ldebugwatchdog

INCLUDEPATH += $$PWD/../../lib
DEPENDPATH += $$PWD/../../lib

QMAKE_RPATHDIR += $ORIGIN
