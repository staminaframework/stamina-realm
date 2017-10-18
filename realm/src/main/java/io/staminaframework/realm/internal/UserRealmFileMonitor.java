/*
 * Copyright (c) 2017 Stamina Framework developers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.staminaframework.realm.internal;

import org.osgi.service.log.LogService;

import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.nio.file.StandardWatchEventKinds.*;

/**
 * This component is responsible for monitoring user realm file.
 * When this file is updated, its content is loaded.
 *
 * @author Stamina Framework developers
 */
class UserRealmFileMonitor {
    interface Listener {
        void userRealmFileUpdated() throws Exception;
    }

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Path userRealmFile;
    private final LogService logService;
    private final Listener listener;
    private WatchService watchService;
    private WatchKey watchKey;
    private Thread worker;
    private boolean initialized;

    public UserRealmFileMonitor(final Path userRealmFile,
                                final Listener listener,
                                final LogService logService) {
        this.userRealmFile = userRealmFile;
        this.listener = listener;
        this.logService = logService;
    }

    public void init() throws IOException {
        logService.log(LogService.LOG_DEBUG, "Initializing user realm file monitor");
        watchService = FileSystems.getDefault().newWatchService();
        watchKey = userRealmFile.getParent().register(watchService, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);

        worker = new Thread() {
            {
                setName("UserAdmin Realm File Monitor");
                setDaemon(false);
                setPriority(Thread.MIN_PRIORITY);
            }

            @Override
            public void run() {
                try {
                    logService.log(LogService.LOG_DEBUG, "Starting user realm file monitor");
                    monitorLoop();
                    logService.log(LogService.LOG_DEBUG, "User realm file monitor stopped");
                } catch (Exception e) {
                    logService.log(LogService.LOG_WARNING,
                            "User realm file monitor stopped with error", e);
                }
            }
        };
        worker.start();
        initialized = true;
    }

    public void dispose() {
        logService.log(LogService.LOG_DEBUG, "Disposing user realm file monitor");
        running.set(false);
        if (watchKey != null) {
            watchKey.cancel();
            watchKey = null;
        }
        if (worker != null) {
            worker.interrupt();
            try {
                worker.join(10 * 10000);
            } catch (InterruptedException ignore) {
            }
            worker = null;
        }
        if (watchService != null) {
            try {
                watchService.close();
            } catch (IOException ignore) {
            }
            watchService = null;
        }
        initialized = false;
    }

    public void updateFileWithoutNotifying(Runnable task) {
        pause();
        try {
            task.run();
        } finally {
            resume();
        }
    }

    public void pause() {
        if (initialized) {
            logService.log(LogService.LOG_DEBUG, "User realm file monitor paused");
            running.set(false);
        }
    }

    public void resume() {
        if (initialized) {
            logService.log(LogService.LOG_DEBUG, "User realm file monitor resumed");
            running.set(true);
        }
    }

    private void monitorLoop() throws Exception {
        boolean looping = true;
        while (looping) {
            final WatchKey wk;
            try {
                // Waiting for a file event...
                wk = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                logService.log(LogService.LOG_DEBUG,
                        "User realm file monitor is about to stop");
                looping = false;
                continue;
            }

            for (final WatchEvent<?> rawEvent : wk.pollEvents()) {
                final WatchEvent.Kind<?> kind = rawEvent.kind();
                if (OVERFLOW.equals(kind)) {
                    // The file is being updated: wait until it's finished.
                    continue;
                }

                final WatchEvent<Path> event = (WatchEvent<Path>) rawEvent;
                final Path fileName = event.context();
                final Path file = userRealmFile.getParent().resolve(fileName);
                if (userRealmFile.equals(file)) {
                    // Check if file monitoring is enabled.
                    if (running.get()) {
                        try {
                            // Handle file update.
                            logService.log(LogService.LOG_DEBUG,
                                    "User realm file updated");
                            listener.userRealmFileUpdated();
                        } catch (Exception e) {
                            logService.log(LogService.LOG_WARNING,
                                    "Error while handling user realm file update", e);
                        }
                    }
                }
            }

            // Prepare for next round.
            looping = watchService != null;
            wk.reset();
        }
    }
}
