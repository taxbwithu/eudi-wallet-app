/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package com.nimbusds.jose.shaded.gson;


import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.Reader;
import java.lang.reflect.Type;

public final class Gson {

    private final com.google.gson.Gson delegate;

    public Gson() {
        this.delegate = new com.google.gson.Gson();
    }

    public Gson(GsonBuilder builder) {
        this.delegate = builder.create();
    }

    public String toJson(Object src) {
        return delegate.toJson(src);
    }

    public String toJson(Object src, Type typeOfSrc) {
        return delegate.toJson(src, typeOfSrc);
    }

    public void toJson(Object src, Appendable writer) {
        delegate.toJson(src, writer);
    }

    public void toJson(Object src, Type typeOfSrc, Appendable writer) {
        delegate.toJson(src, typeOfSrc, writer);
    }

    public void toJson(Object src, Type typeOfSrc, JsonWriter writer) {
        delegate.toJson(src, typeOfSrc, writer);
    }

    public <T> T fromJson(String json, Class<T> classOfT) {
        return delegate.fromJson(json, classOfT);
    }

    public <T> T fromJson(Reader json, Class<T> classOfT) {
        return delegate.fromJson(json, classOfT);
    }

    public <T> T fromJson(String json, Type typeOfT) {
        return delegate.fromJson(json, typeOfT);
    }

    public <T> T fromJson(Reader json, Type typeOfT) {
        return delegate.fromJson(json, typeOfT);
    }

    public <T> T fromJson(JsonReader reader, Type typeOfT) {
        return delegate.fromJson(reader, typeOfT);
    }

    public <T> TypeAdapter<T> getAdapter(Class<T> type) {
        return delegate.getAdapter(type);
    }

    public <T> TypeAdapter<T> getAdapter(TypeToken<T> type) {
        return delegate.getAdapter(type);
    }
}
