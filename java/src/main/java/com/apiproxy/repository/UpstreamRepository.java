package com.apiproxy.repository;

import com.apiproxy.entity.Upstream;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UpstreamRepository extends JpaRepository<Upstream, String> {

    /** 启用状态的上游，按优先级升序（数字越小优先级越高，对齐 Python priority 排序） */
    List<Upstream> findByEnabledOrderByPriorityAsc(Integer enabled);

    /** 全部启用上游（refreshModels 拉取模型目录时使用，顺序无关） */
    List<Upstream> findByEnabled(Integer enabled);

    /** 全部上游按优先级、名称排序（管理后台列表 / reloadFromDb） */
    List<Upstream> findAllByOrderByPriorityAscNameAsc();
}
