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

plugins {
    java
    `maven-publish`
}

group = "com.nimbusds"
version = "LOCAL" // Avoid conflict with Maven Central

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
}

dependencies {
    implementation("net.minidev:json-smart:2.4.8")
    implementation("com.github.stephenc.jcip:jcip-annotations:1.0-1")
//    implementation("net.jcip:jcip-annotations:1.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.81")
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    implementation("com.google.crypto.tink:tink-android:1.18.0")
    implementation("com.google.code.gson:gson:2.12.1")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}