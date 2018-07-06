package com.reamls;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashSet;
import java.util.Set;

public class ShiroReamls extends AuthorizingRealm {

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
        //3 realmName  当前realm对象的那么 调用父类的getName方法即可 这里有用到反射机制

        if ("admin".equals(username)) {
            credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
        } else if ("user".equals(username)) {
            credentials = "098d2c478e9c11555ce2823231e02ec1";
        }

        String realmName = getName();


        SimpleAuthenticationInfo info = null; // new SimpleAuthenticationInfo(username, credentials, realmName);
        //盐值加密
        ByteSource salt = ByteSource.Util.bytes(username);
        info = new SimpleAuthenticationInfo(username, credentials, salt, realmName);

        return info;

    }

    public static void main(String[] args) {
        String md5 = "md5";
        Object obj = "123456";
        Object salt = ByteSource.Util.bytes("user");
        int hashIterations = 1024;

        SimpleHash simpleHash = new SimpleHash(md5, obj, salt, hashIterations);
        System.out.println(simpleHash);
    }

    //授权会被 shiro 回掉的方法
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("doGetAuthorizationInfo");
        //1 从 principalCollection 获取登录用户的信息
        Object princcipal = principalCollection.getPrimaryPrincipal();
        //2 利用登录用户的信息 来获取当前用户的角色或权限
        Set<String> roles = new HashSet<>();
        roles.add("user");
        if ("admin".equals(princcipal)) {
            roles.add("admin");
        }
        //3 创建 SimpleAuthorizationInfo 并设置器reles属性
        SimpleAuthorizationInfo s = new SimpleAuthorizationInfo(roles);
        //4 返回该对象
        return s;
    }
}
