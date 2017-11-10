extern "C" {
#include <debugwatchdoglib.h>
}

#include <signal.h>
#include <unistd.h>

#include <QProcess>
#include <QStringListModel>

#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow* MainWindow::globalInstance = NULL;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow) {

    debugWatchdogLibraryInitialized = false;
    fatalErrorOccurred = false;

    ui->setupUi(this);

    setSuccessStatusMessage("OK");

    ui->stoppedProcessesListView->setModel(new QStringListModel(QStringList(), NULL));
    ui->stoppedProcessesListView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->stoppedProcessesListView->setSelectionMode(QAbstractItemView::SelectionMode::SingleSelection);

    ui->watchedBinariesListView->setModel(new QStringListModel(QStringList(), NULL));
    ui->watchedBinariesListView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->watchedBinariesListView->setSelectionMode(QAbstractItemView::SelectionMode::SingleSelection);

    connect(ui->onOffCheckBox, SIGNAL(stateChanged(int)), this, SLOT(onOffCheckBoxStateChanged(int)));
    connect(ui->watchButton, SIGNAL(clicked()), this, SLOT(watchButtonClicked()));
    connect(ui->unwatchButton, SIGNAL(clicked()), this, SLOT(unwatchButtonClicked()));
    connect(ui->killButton, SIGNAL(clicked()), this, SLOT(killButtonClicked()));
    connect(ui->continueButton, SIGNAL(clicked()), this, SLOT(continueButtonClicked()));
    connect(ui->debugButton, SIGNAL(clicked()), this, SLOT(debugButtonClicked()));
    connect(ui->binaryToWatchText, SIGNAL(blockCountChanged(int)), this, SLOT(binaryToWatchTextEnterPressed(int)));
    connect(ui->stoppedProcessesListView->selectionModel(), SIGNAL(currentRowChanged(const QModelIndex&, const QModelIndex&)),
    this, SLOT(stoppedProcessesItemSelectionChanged(const QModelIndex &, const QModelIndex &)));
    connect(ui->watchedBinariesListView->selectionModel(), SIGNAL(currentRowChanged(const QModelIndex&, const QModelIndex&)),
    this, SLOT(watchedBinariesItemSelectionChanged(const QModelIndex &, const QModelIndex &)));

    MainWindow::globalInstance = this;
    dwlib_set_fatal_error_handler(&MainWindow::fatalErrorHandler);
}

void MainWindow::stoppedProcessCallback(pid_t pid) {
    if (MainWindow::globalInstance->fatalErrorOccurred) { return; }
    QMutexLocker l(&MainWindow::globalInstance->globalMutex);
    QStringListModel* model = (QStringListModel*)MainWindow::globalInstance->ui->stoppedProcessesListView->model();
    QString rowText = QString::number(pid);
    QString executableBinaryPath = MainWindow::getProcessExecutableBinary(pid);
    if (executableBinaryPath.size() > 0) {
        rowText += QString(" - ") + executableBinaryPath;
    }
    model->insertRow(0);
    QModelIndex index = model->index(0);
    model->setData(index, rowText);
}

void MainWindow::binaryToWatchTextEnterPressed(int) {
    if (fatalErrorOccurred) { return; }
    {
        bool signalsOldState = ui->binaryToWatchText->blockSignals(true);
        ui->binaryToWatchText->setPlainText(ui->binaryToWatchText->toPlainText().split("\n")[0]);
        ui->binaryToWatchText->blockSignals(signalsOldState);
    }
    MainWindow::watchButtonClicked();
}

void MainWindow::watchButtonClicked(void) {
    if (fatalErrorOccurred) { return; }
    bool success = false;
    QString binaryToWatch = ui->binaryToWatchText->toPlainText();
    if (binaryToWatch.size()  > 0) {
        if (debugWatchdogLibraryInitialized) {
            if (dwlib_watch(binaryToWatch.toUtf8().data()) == DWLIB_SUCCESS) {
                success = true;
            }
        } else {
            success = true;
        }
    }
    if (success) {
        QStringListModel* model = (QStringListModel*)ui->watchedBinariesListView->model();
        model->insertRow(model->rowCount());
        QModelIndex index = model->index(model->rowCount()-1);
        model->setData(index, binaryToWatch);
        setSuccessStatusMessage("Executable binary added to watched list.");
    } else {
        setFailureStatusMessage("Error adding executable binary to watched list.");
    }
    ui->binaryToWatchText->setPlainText("");
}

void MainWindow::unwatchButtonClicked(void) {
    if (fatalErrorOccurred) { return; }
    bool success = false;
    QString selectedWatchedBinary = getSelectedWatchedBinary();
    if (selectedWatchedBinary.size() > 0) {
        if (debugWatchdogLibraryInitialized) {
            if (dwlib_unwatch(selectedWatchedBinary.toUtf8().data()) == DWLIB_SUCCESS) {
                success = true;
            }
        } else {
            success = true;
        }
    }
    if (success) {
        QStringListModel* model = (QStringListModel*)ui->watchedBinariesListView->model();
        model->removeRow(ui->watchedBinariesListView->currentIndex().row());
        setSuccessStatusMessage("Executable binary removed from watched list.");
    } else {
        setFailureStatusMessage("Error removing executable binary from watched list.");
    }
}

void MainWindow::killButtonClicked(void) {
    if (fatalErrorOccurred) { return; }
    pid_t selectedStoppedProcessPid = getSelectedStoppedProcessPid();
    if (selectedStoppedProcessPid > 0) {
        if (kill(selectedStoppedProcessPid, SIGKILL) == 0) {
            setSuccessStatusMessage("Process killed: " + QString::number(selectedStoppedProcessPid));
        } else {
            setFailureStatusMessage("Process could not be killed.");
        }
        removeCurrentSelectedStoppedProcess();
    } else {
        setFailureStatusMessage("Cannot kill process.");
    }
}

void MainWindow::continueButtonClicked(void) {
    if (fatalErrorOccurred) { return; }
    pid_t selectedStoppedProcessPid = getSelectedStoppedProcessPid();
    if (selectedStoppedProcessPid > 0) {
        if (kill(selectedStoppedProcessPid, SIGCONT) == 0) {
            setSuccessStatusMessage("Process continued: " + QString::number(selectedStoppedProcessPid));
        } else {
            setFailureStatusMessage("Cannot continue process.");
        }
        removeCurrentSelectedStoppedProcess();
    } else {
        setFailureStatusMessage("Cannot continue process.");
    }
}

void MainWindow::debugButtonClicked(void) {
    if (fatalErrorOccurred) { return; }
    pid_t selectedStoppedProcessPid = getSelectedStoppedProcessPid();
    if (selectedStoppedProcessPid > 0) {
        QString gdbStartCommand = QString("dbus-launch gnome-terminal -x gdb -p ") +
                QString::number(selectedStoppedProcessPid);
        QProcess::startDetached(gdbStartCommand);
        setSuccessStatusMessage("Process debugged: " + QString::number(selectedStoppedProcessPid));
        removeCurrentSelectedStoppedProcess();
    } else {
        setFailureStatusMessage("Cannot debug process.");
    }
}

void MainWindow::onOffCheckBoxStateChanged(int) {
    if (fatalErrorOccurred) { return; }
    bool success = false;
    if (ui->onOffCheckBox->isChecked()) {
        if (dwlib_initialize(&MainWindow::stoppedProcessCallback) == DWLIB_SUCCESS) {
            QStringListModel* model = (QStringListModel*)ui->watchedBinariesListView->model();
            bool failedExecutableBinaryWatch = false;
            for (int i = 0; i < model->rowCount(); i++) {
                if (dwlib_watch(model->index(i).data().toString().toUtf8().data()) != DWLIB_SUCCESS) {
                    failedExecutableBinaryWatch = true;
                    break;
                }
            }
            if (failedExecutableBinaryWatch) {
                dwlib_finalize();
            } else {
                success = true;
            }
        }
        if (success) {
            debugWatchdogLibraryInitialized = true;
            setSuccessStatusMessage("Debug Watchdog is now ON.");
        } else {
            {
                bool signalsOldState = ui->onOffCheckBox->blockSignals(true);
                ui->onOffCheckBox->setChecked(false);
                ui->onOffCheckBox->blockSignals(signalsOldState);
            }
            setFailureStatusMessage("Debug Watchdog could not be turned ON.");
        }
    } else {
        if (dwlib_finalize() == DWLIB_SUCCESS) {
            success = true;
        }
        if (success) {
            debugWatchdogLibraryInitialized = false;
            setSuccessStatusMessage("Debug Watchdog is now OFF.");
        } else {
            {
                bool signalsOldState = ui->onOffCheckBox->blockSignals(true);
                ui->onOffCheckBox->setChecked(true);
                ui->onOffCheckBox->blockSignals(signalsOldState);
            }
            setFailureStatusMessage("Debug Watchdog could not be turned OFF.");
        }
    }
}

void MainWindow::watchedBinariesItemSelectionChanged(const QModelIndex& index, const QModelIndex&) {
    if (index.row() >= 0) {
        bool signalsOldState = ui->stoppedProcessesListView->blockSignals(true);
        ui->stoppedProcessesListView->clearSelection();
        ui->stoppedProcessesListView->setCurrentIndex(QModelIndex());
        ui->stoppedProcessesListView->blockSignals(signalsOldState);
    }
}

void MainWindow::stoppedProcessesItemSelectionChanged(const QModelIndex & index, const QModelIndex&) {
    if (index.row() >= 0) {
        bool signalsOldState = ui->watchedBinariesListView->blockSignals(true);
        ui->watchedBinariesListView->clearSelection();
        ui->watchedBinariesListView->setCurrentIndex(QModelIndex());
        ui->watchedBinariesListView->blockSignals(signalsOldState);
    }
}

void MainWindow::mousePressEvent(QMouseEvent* event) {
    if(event->button() == Qt::LeftButton) {
        {
            bool signalsOldState = ui->watchedBinariesListView->blockSignals(true);
            ui->watchedBinariesListView->clearSelection();
            ui->watchedBinariesListView->setCurrentIndex(QModelIndex());
            ui->watchedBinariesListView->blockSignals(signalsOldState);
        }
        {
            bool signalsOldState = ui->stoppedProcessesListView->blockSignals(true);
            ui->stoppedProcessesListView->clearSelection();
            ui->stoppedProcessesListView->setCurrentIndex(QModelIndex());
            ui->stoppedProcessesListView->blockSignals(signalsOldState);
        }
    }
}

void MainWindow::fatalErrorHandler(int) {
    MainWindow::globalInstance->fatalErrorOccurred = true;
    MainWindow::globalInstance->setFailureStatusMessage("Fatal error occurred.");
    MainWindow::globalInstance->ui->onOffCheckBox->setCheckable(false);
    MainWindow::globalInstance->ui->onOffCheckBox->setEnabled(false);
    MainWindow::globalInstance->ui->binaryToWatchText->setEnabled(false);
    MainWindow::globalInstance->ui->stoppedProcessesListView->setEnabled(false);
    MainWindow::globalInstance->ui->watchedBinariesListView->setEnabled(false);
    MainWindow::globalInstance->ui->binaryToWatchText->setEnabled(false);
    MainWindow::globalInstance->ui->watchButton->setEnabled(false);
    MainWindow::globalInstance->ui->unwatchButton->setEnabled(false);
    MainWindow::globalInstance->ui->killButton->setEnabled(false);
    MainWindow::globalInstance->ui->continueButton->setEnabled(false);
    MainWindow::globalInstance->ui->debugButton->setEnabled(false);
}

void MainWindow::setSuccessStatusMessage(const QString& m) {
    ui->statusMessage->setStyleSheet("QLabel { color : green; }");
    ui->statusMessage->setText(m);
}

void MainWindow::setFailureStatusMessage(const QString& m) {
    ui->statusMessage->setStyleSheet("QLabel { color : red; }");
    ui->statusMessage->setText(m);
}

void MainWindow::removeCurrentSelectedStoppedProcess(void) {
    QMutexLocker l(&globalMutex);
    QStringListModel* model = (QStringListModel*)ui->stoppedProcessesListView->model();
    model->removeRow(ui->stoppedProcessesListView->currentIndex().row());
}

pid_t MainWindow::getSelectedStoppedProcessPid(void) {
    QMutexLocker l(&globalMutex);
    QString processRowText = ui->stoppedProcessesListView->currentIndex().data().toString();
    return processRowText.split("-")[0].toInt();
}

QString MainWindow::getSelectedWatchedBinary(void) {
    return ui->watchedBinariesListView->currentIndex().data().toString();
}

MainWindow::~MainWindow() {
    delete ui;
}

QString MainWindow::getProcessExecutableBinary(pid_t p) {
    QString ret;
    ssize_t count = -1;
    QString executableBinaryLinkPath = QString("/proc/") + QString::number(p) + QString("/exe");
    char* executable_full_path = (char*)malloc(PATH_MAX);
    if (executable_full_path == NULL) {
        goto cleanup;
    }
    memset(executable_full_path, 0, PATH_MAX);
    count = readlink(executableBinaryLinkPath.toUtf8().data(), executable_full_path, PATH_MAX);
    if (count == -1) {
        goto cleanup;
    }
    ret = QString(executable_full_path);
cleanup:
    if (executable_full_path != NULL) {
        free(executable_full_path);
        executable_full_path = NULL;
    }
    return ret;
}
