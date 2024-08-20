# Danny 博客

## 站点目录结构

https://docs.hugoblox.com/reference/site-structure/

```shell
➜  Danny5487401.github.io git:(main) tree -L 1 .                
.
├── LICENSE.md 
├── README.md
├── assets # 图片视频
├── config # 配置
├── content # 内容
├── go.mod
├── go.sum
├── hugo_stats.json
├── netlify.toml
├── notebooks
├── resources
└── static # 可下载文件
```

### 配置文件

> The root configuration keys are build, caches, cascade, deployment, frontmatter, imaging, languages, markup, mediatypes,
menus, minify, module, outputformats, outputs, params, permalinks, privacy, related, security, segments, server, services, sitemap, and taxonomies.



### 索引页面: _index.md

_index.md索引页面在Hugo内容中是个特殊角色。它允许您在列表模板中添加前置设置和内容。
这些列表模板包括区块模板, tag模板,tag列表模板和您的主页模板。


### 图片处理


- 全局资源是位于 assets 目录中或装载到 assets 目录中任意目录中的文件。
- 页面资源是页面束（page bundle）中的文件。页面束是一个具有根目录下的 index.md 或 _index.md 文件的目录


使用 [shortcodes ](https://gohugo.io/content-management/shortcodes/#figure)
```markdown
{{<figure src="./informer.png#center" width=800px >}}
```

### 菜单 menu

3 种方式

- 自动定义
- 在 front matter 正文区域
- In site configuration


## 命令使用

```shell
✗ hugo version
hugo v0.120.4-f11bca5fec2ebb3a02727fb2a5cfb08da96fd9df+extended darwin/arm64 BuildDate=2023-11-08T11:18:07Z VendorInfo=brew

```

### 添加内容
```shell
✗ hugo new content content/kubernetes/workqueue/index.md
```


### 本地调试

```shell
✗ hugo server --minify --buildDrafts
```


### 发布


实际提交代码触发 GitHub Actions







## 参考
- [HugoBlox本文模版](https://github.com/HugoBlox/theme-blog)
- [hugoblox 文档](https://docs.hugoblox.com/)
- [hugo 官方中文文档](https://hugo.opendocs.io/content-management/)
- [hugo 官方英文文档](https://gohugo.io/documentation/)


