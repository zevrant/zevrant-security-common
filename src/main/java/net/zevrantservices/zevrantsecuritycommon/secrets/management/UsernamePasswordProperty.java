package net.zevrantservices.zevrantsecuritycommon.secrets.management;

public class UsernamePasswordProperty {

    private String username;
    private String password;

    public UsernamePasswordProperty() {
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
