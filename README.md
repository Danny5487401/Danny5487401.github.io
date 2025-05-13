<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Danny 博客](#danny-%E5%8D%9A%E5%AE%A2)
  - [基本知识](#%E5%9F%BA%E6%9C%AC%E7%9F%A5%E8%AF%86)
    - [Front-matter 前言](#front-matter-%E5%89%8D%E8%A8%80)
    - [page bundle: https://gohugo.io/content-management/page-bundles/](#page-bundle-httpsgohugoiocontent-managementpage-bundles)
  - [配置](#%E9%85%8D%E7%BD%AE)
    - [配置文件](#%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6)
    - [索引页面: _index.md](#%E7%B4%A2%E5%BC%95%E9%A1%B5%E9%9D%A2-_indexmd)
    - [菜单 menu](#%E8%8F%9C%E5%8D%95-menu)
  - [markdown 使用: https://docs.hugoblox.com/reference/markdown/](#markdown-%E4%BD%BF%E7%94%A8-httpsdocshugobloxcomreferencemarkdown)
    - [图片处理](#%E5%9B%BE%E7%89%87%E5%A4%84%E7%90%86)
  - [命令使用](#%E5%91%BD%E4%BB%A4%E4%BD%BF%E7%94%A8)
    - [添加内容](#%E6%B7%BB%E5%8A%A0%E5%86%85%E5%AE%B9)
    - [本地调试](#%E6%9C%AC%E5%9C%B0%E8%B0%83%E8%AF%95)
    - [发布](#%E5%8F%91%E5%B8%83)
  - [升级 Hugo Themes or Plugins](#%E5%8D%87%E7%BA%A7-hugo-themes-or-plugins)
  - [扩展:https://docs.hugoblox.com/reference/extend/](#%E6%89%A9%E5%B1%95httpsdocshugobloxcomreferenceextend)
  - [参考](#%E5%8F%82%E8%80%83)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Danny 博客

## 基本知识
![](.README_images/blog_section.png)
### Front-matter 前言

[**Front-matter**](https://docs.hugoblox.com/reference/front-matter/) 是 markdown 文件最上方以 --- 分隔的区域，用于指定个别markdown的变量。

```markdown
---
title: Blogging Like a Hacker
lang: en-US
---
```

### page bundle: https://gohugo.io/content-management/page-bundles/

```shell
# this site has an “about” page and a “privacy” page:
content/
├── about/ # 这个是 page bundle 
│   ├── index.md
│   └── welcome.jpg
└── privacy.md
```


## 配置

[站点目录结构](https://docs.hugoblox.com/reference/site-structure/)

```shell
$ tree -L 2 .
.
├── LICENSE.md
├── README.md
├── assets
│   └── media
├── config
│   └── _default
├── content
│   ├── _index.md
│   ├── authors
│   ├── en
│   ├── golang
│   ├── kubernetes
│   ├── post
│   ├── security
│   ├── tags
│   ├── uses.md
│   └── zh
├── go.mod # 升级使用
├── go.sum
├── hugo_stats.json
├── netlify.toml
├── notebooks
│   └── blog-with-jupyter.ipynb
├ # ...
├── resources
│   └── _gen
└── static
    └── uploads # 阅读者可以下载的文件

```



### 配置文件

> The root configuration keys are build, caches, cascade, deployment, frontmatter, imaging, languages, markup, mediatypes,
menus, minify, module, outputformats, outputs, params, permalinks, privacy, related, security, segments, server, services, sitemap, and taxonomies.



### 索引页面: _index.md

_index.md索引页面在Hugo内容中是个特殊角色。它允许您在列表模板中添加前置设置和内容。
这些列表模板包括区块模板, tag模板,tag列表模板和您的主页模板。


### 菜单 menu

3 种方式

- 自动定义
- 在 front matter 正文区域
- In site configuration



## markdown 使用: https://docs.hugoblox.com/reference/markdown/




### 图片处理

- 全局资源是位于 assets 目录中或装载到 assets 目录中任意目录中的文件,这里是 assets/media/
- 页面资源是页面束（page bundle）中的文件。




1. 使用 [shortcodes](https://gohugo.io/content-management/shortcodes/#figure)
```markdown
{{<figure src="informer.png#center" width=800px >}}
```

2. 引用全局资源
![deltaFIFO 队列架构](deltafifo.png "deltaFIFO 队列")


## 命令使用


```shell
# hugo 版本
✗ hugo version
hugo v0.139.0+extended+withdeploy darwin/arm64 BuildDate=2024-11-18T16:17:45Z VendorInfo=brew
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



## 升级 Hugo Themes or Plugins

插件当前在单独的文件 config/_default/module.yaml 

1. 更改 go.mod 版本
```shell
hugo mod get -u github.com/HugoBlox/hugo-blox-builder/modules/blox-tailwind@v0.3.1
```
2. 更改 github 流水线 WC_HUGO_VERSION 兼容版本


## 扩展:https://docs.hugoblox.com/reference/extend/


## 参考
- [Hugo Academic Blog Theme 本文采用的模版](https://github.com/HugoBlox/theme-blog)
- [hugoblox 文档](https://docs.hugoblox.com/)
- [hugo 官方中文文档](https://hugo.opendocs.io/content-management/)
- [hugo 官方英文文档](https://gohugo.io/documentation/)


