package io.radarlume.domain;

import java.util.List;

public interface InventoryRepository {
    void save(Inventory inventory);
    List<Inventory> recent(int limit);
    void deleteAll();
}
