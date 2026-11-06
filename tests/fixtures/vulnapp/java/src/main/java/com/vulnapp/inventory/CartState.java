package com.vulnapp.inventory;

import java.io.Serializable;
import java.util.List;

public record CartState(String owner, List<String> items) implements Serializable {
}
