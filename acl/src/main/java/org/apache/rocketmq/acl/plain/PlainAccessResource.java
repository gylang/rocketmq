/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rocketmq.acl.plain;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.rocketmq.acl.AccessResource;
import org.apache.rocketmq.common.MixAll;

public class PlainAccessResource implements AccessResource {

    // Identify the user
    private String accessKey;

    /** 秘钥/密码 */
    private String secretKey;
    /** 远程地址 */
    private String whiteRemoteAddress;
    /** 是否为管理员 */
    private boolean admin;
    /** 默认topic权限 */
    private byte defaultTopicPerm = 1;
    /** 默认组权限 */
    private byte defaultGroupPerm = 1;
    /** 资源权限 */
    private Map<String, Byte> resourcePermMap;
    /** 远程地址策略校验 白名单校验 */
    private RemoteAddressStrategy remoteAddressStrategy;
   /** 请求码(命令 指令) */
    private int requestCode;

    // The content to calculate the content
    private byte[] content;
    /** 签名值 */
    private String signature;
    /** 秘钥token */
    private String secretToken;

    private String recognition;

    public PlainAccessResource() {
    }

    public static boolean isRetryTopic(String topic) {
        return null != topic && topic.startsWith(MixAll.RETRY_GROUP_TOPIC_PREFIX);
    }

    public static String printStr(String resource, boolean isGroup) {
        if (resource == null) {
            return null;
        }
        if (isGroup) {
            return String.format("%s:%s", "group", getGroupFromRetryTopic(resource));
        } else {
            return String.format("%s:%s", "topic", resource);
        }
    }

    public static String getGroupFromRetryTopic(String retryTopic) {
        if (retryTopic == null) {
            return null;
        }
        return retryTopic.substring(MixAll.RETRY_GROUP_TOPIC_PREFIX.length());
    }

    public static String getRetryTopic(String group) {
        if (group == null) {
            return null;
        }
        return MixAll.getRetryTopic(group);
    }

    public void addResourceAndPerm(String resource, byte perm) {
        if (resource == null) {
            return;
        }
        if (resourcePermMap == null) {
            resourcePermMap = new HashMap<>();
        }
        resourcePermMap.put(resource, perm);
    }

    public String getAccessKey() {
        return accessKey;
    }

    public void setAccessKey(String accessKey) {
        this.accessKey = accessKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getWhiteRemoteAddress() {
        return whiteRemoteAddress;
    }

    public void setWhiteRemoteAddress(String whiteRemoteAddress) {
        this.whiteRemoteAddress = whiteRemoteAddress;
    }

    public boolean isAdmin() {
        return admin;
    }

    public void setAdmin(boolean admin) {
        this.admin = admin;
    }

    public byte getDefaultTopicPerm() {
        return defaultTopicPerm;
    }

    public void setDefaultTopicPerm(byte defaultTopicPerm) {
        this.defaultTopicPerm = defaultTopicPerm;
    }

    public byte getDefaultGroupPerm() {
        return defaultGroupPerm;
    }

    public void setDefaultGroupPerm(byte defaultGroupPerm) {
        this.defaultGroupPerm = defaultGroupPerm;
    }

    public Map<String, Byte> getResourcePermMap() {
        return resourcePermMap;
    }

    public String getRecognition() {
        return recognition;
    }

    public void setRecognition(String recognition) {
        this.recognition = recognition;
    }

    public int getRequestCode() {
        return requestCode;
    }

    public void setRequestCode(int requestCode) {
        this.requestCode = requestCode;
    }

    public String getSecretToken() {
        return secretToken;
    }

    public void setSecretToken(String secretToken) {
        this.secretToken = secretToken;
    }

    public RemoteAddressStrategy getRemoteAddressStrategy() {
        return remoteAddressStrategy;
    }

    public void setRemoteAddressStrategy(RemoteAddressStrategy remoteAddressStrategy) {
        this.remoteAddressStrategy = remoteAddressStrategy;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}
