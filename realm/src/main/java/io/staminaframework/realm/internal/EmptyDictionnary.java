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

import java.util.Collections;
import java.util.Dictionary;
import java.util.Enumeration;

class EmptyDictionnary<K, V> extends Dictionary<K, V> {
    public static Dictionary INSTANCE = new EmptyDictionnary();

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        return obj instanceof EmptyDictionnary;
    }

    @Override
    public int size() {
        return 0;
    }

    @Override
    public boolean isEmpty() {
        return true;
    }

    @Override
    public Enumeration<K> keys() {
        return Collections.emptyEnumeration();
    }

    @Override
    public Enumeration<V> elements() {
        return Collections.emptyEnumeration();
    }

    @Override
    public V get(Object key) {
        if (key == null) {
            throw new NullPointerException("Key is null");
        }
        return null;
    }

    @Override
    public V put(K key, V value) {
        if (key == null) {
            throw new NullPointerException("Key is null");
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public V remove(Object key) {
        if (key == null) {
            throw new NullPointerException("Key is null");
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
        return "<empty dictionary>";
    }
}
