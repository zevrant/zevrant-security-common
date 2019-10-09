package net.zevrantservices.zevrantsecuritycommon.secrets.management;

public class UsernamePasswordProperty {

    private String username;
    private String password;

    public UsernamePasswordProperty() {
    }

    public UsernamePasswordProperty(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
