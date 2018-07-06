package com.reamls;

import org.apache.shiro.authc.*;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

public class SecondRealm extends AuthenticatingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("第一个Realm");
        //把AuthenticationInfo 转换为UsernamePasswordToken
        UsernamePasswordToken UpToken = (UsernamePasswordToken) token;
        //从UsernamePasswordToken中获取Username
        String username = UpToken.getUsername();
        //调用数据库查询方法 从数据中查询Username
        System.out.println("从数据库中获取Uusename   " + username);
        //若用户不在则跑出UnknownAccountException异常
        if ("unknown".equals(username)) {
            throw new UnknownAccountException("用户不存在");
        }
        //根据用户信息的情况，决定是否需要抛出AuthenticationException异常
        if ("monster".equals(username)) {
            throw new LockedAccountException("用户被锁定");
        }

        //根据用户情况来构建AuthenticationInfo 对象并返回
        //1 principal 认证的实体信息 可一是Username 或者是对应的数据据实体表映射对象
        //2 credentials 从数据中获取的密码
        Object credentials = null; //"fc1709d0a95a6be30bc5926fdb7f22f4";
        //3 realmName  当前realm对象的那么 调用父类的getName方法即可

        if ("admin".equals(username)) {
            credentials = "ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
        } else if ("user".equals(username)) {
            credentials = "073d4c3ae812935f23cb3f2a71943f49e082a718";
        }

        String realmName = getName();


        SimpleAuthenticationInfo info = null; // new SimpleAuthenticationInfo(username, credentials, realmName);
        //盐值加密
        ByteSource salt = ByteSource.Util.bytes(username);
        info = new SimpleAuthenticationInfo(username, credentials, salt, realmName);

        return info;

    }

    public static void main(String[] args) {
        String md5 = "SHA1";
        Object obj = "123456";
        Object salt = ByteSource.Util.bytes("user");
        int hashIterations = 1024;

        SimpleHash simpleHash = new SimpleHash(md5, obj, salt, hashIterations);
        System.out.println(simpleHash);
    }

}
