var currentNode = null;
var templateTable;

$(document).ready(function(){
  var canvas = document.getElementById('canvas'); 
  var stage = new JTopo.Stage(canvas); // 创建一个舞台对象

  var scene = new JTopo.Scene(stage); // 创建一个场景对象
  // scene.background = '/static/images/bg.jpg';
  scene.alpha = 1;
  scene.backgroundColor = '242,242,242';  
  
  // 创建公网节点
  var local = createSingleNode({
    x: 350,
    y: 200,
    w: 128,
    h: 128,
    text: 'Orchestrator',
    img: 'control-cloud.png',
    dragable: false
  }, scene);

  // makeNodeEditable(scene);

  var menuList = $('#contextmenu'),
  menuItem = menuList.find('a');
  
  menuItem.click(function() {
    if($(this)[0].id === 'config-template') {
      $('#config-template-modal').modal();
      if(!templateTable) {
        templateTable = $('#templates').DataTable({
          ajax: {
            url: '/api_templates/' + currentNode.text
          },
          pageLength: 5,
          columns: [{
            data: "tid"
          }, {
            data: "name"
          }, {
            data: "applied"
          }],
          columnDefs: [
          {
            render: function(data, type, row, meta) {
              // return '<a href="' + data + '" target="_blank">' + row.title + '</a>';
              if (data) {
                return '<button class="btn btn-primary" disabled style="margin-right: 10px">已应用</button><button class="btn btn-primary" onclick="editTemplate("' + row.tid + ')">编辑模板</button>';
              } else {
                return '<button class="btn btn-primary" style="margin-right: 10px" onclick="applyTemplate(' + row.tid + ')">应用</button><button class="btn btn-primary" onclick="editTemplate(' + row.tid + ')">编辑模板</button>';                
              }           
            },
            //指定是第三列
            targets: 2
          }]
        });
        // templateTable.on('order.dt search.dt', function() {
        //     t.column(0, {
        //       "search": 'applied',
        //       "order": 'applied'
        //     }).nodes().each(function(cell, i) {
        //       cell.innerHTML = i + 1;
        //   });
        // }).draw();
      }
    } 
    menuList.hide();
  });

  stage.click(function(event) {
    if (event.button === 0) {
      menuList.hide();
    }
  });

  getNodes(function(nodeList) {
    nodeList.forEach(function(node){
      node.x = randomNodePosition('x');
      node.y = randomNodePosition('y');
      node.w = 40;
      node.h = 40;
      node.text = node.node_name;
      node.img = node.node_type === 'agent' ? 'terminal.png' : 'switch.png';
      node.dragable = true;
    })
    var addedNodeList = createNodes(nodeList, scene);
    for (var i = 0, j = addedNodeList.length;i < j;i++) {
      createLink(addedNodeList[i], local, '', scene);
    }
  });
  // var nodeList = simulateNodes();
  // var addedNodeList = createNodes(nodeList, scene);
  // for (var i = 0, j = addedNodeList.length;i < j;i++) {
  //   createLink(addedNodeList[i], local, '', scene);
  // }
});

// 模拟生成节点
function simulateNodes () {
  var nodeList = [];

  for (var i = 0;i < 5; i++) {
    var singleNode = {
      x: Math.random() * 800,
      y: Math.random() * 500,
      w: 40,
      h: 40,
      img: 'terminal.png',
      dragable: true,
      text: 'Node ' + i
    }
    nodeList.push(singleNode);
  }

  return nodeList;
}

// 生成节点位置
function randomNodePosition(type) {
  var result;
  if (type === 'x') {
    result = Math.random() * 800;
    if(result >= 320 && result <= 560) {
      return randomNodePosition('x');
    }
    else {
      return result;
    }
  } else {
    result = Math.random() * 500;
    if(result >= 170 && result <= 410) {
      return randomNodePosition('y');
    }
    else {
      return result;
    }
  }
}

// 添加节点数组至拓扑
function createNodes (nodeList, scene) {
  var addedNodeList = []
  for (var i = 0, j = nodeList.length;i < j;i++) {
    var node = nodeList[i];
    var addedNode = createSingleNode(node, scene);
    addedNodeList.push(addedNode);
  }
  return addedNodeList;
}

// 添加单个节点至拓扑
function createSingleNode (nodeInfo, scene) {
  console.log(nodeInfo);
  var node = new JTopo.Node(nodeInfo.text);
  node.setLocation(nodeInfo.x, nodeInfo.y);
  node.setSize(nodeInfo.w, nodeInfo.h);
  if (nodeInfo.img) {
    node.setImage('/static/images/' + nodeInfo.img, false);
  }
  node.dragable = nodeInfo.dragable;
  if(nodeInfo.node_state === 'up') {
    node.alarm = 'up';
    node.alarmColor = '0, 255, 0';
  } else if (nodeInfo.node_state === 'down') {
    node.alarm = 'down';
  }
  node.fontColor = nodeInfo.fontColor || '0,0,0';  
  scene.add(node);
  if (nodeInfo.node_type === 'agent') {
    node.addEventListener('mouseup', function(event) {
      handler(event, node);
    });
  }
  return node;
}

// 创建节点间连线
function createLink (fromNode, toNode, text, scene) {
  var link = new JTopo.Link(fromNode, toNode, text);
  link.lineWidth = 3;
  link.dashedPattern = 5;
  link.bundleOffset = 60; // 折线拐角处的长度
  link.bundleGap = 20; // 线条之间的间隔
  link.textOffsetY = 3; // 文本偏移量（向下3个像素）
  link.strokeColor = '81,181,220';  
  scene.add(link);
  return link;
}

// 创建动态连线
function makeNodeEditable (scene) { 
  var beginNode = null;

  var tempNodeA = new JTopo.Node('tempA');;
  tempNodeA.setSize(1, 1);
  
  var tempNodeZ = new JTopo.Node('tempZ');;
  tempNodeZ.setSize(1, 1);
  
  var link = new JTopo.Link(tempNodeA, tempNodeZ);
  
  scene.mouseup(function(e) {
    if (e.button === 2) {
      scene.remove(link);
      return;
    }
    if (e.target !== null && e.target instanceof JTopo.Node) {
      if (beginNode === null) {
        beginNode = e.target;
        scene.add(link);
        tempNodeA.setLocation(e.x, e.y);
        tempNodeZ.setLocation(e.x, e.y);
      } else if (beginNode !== e.target) {
        var endNode = e.target;
        var l = new JTopo.Link(beginNode, endNode);
        scene.add(l);
        beginNode = null;
        scene.remove(link);
      } else {
        beginNode = null;
      }
    } else {
      scene.remove(link);
    }
  });
  
  scene.mousedown(function(e){
    if(e.target == null || e.target === beginNode || e.target === link){
      scene.remove(link);
    }
  });

  scene.mousemove(function(e){
    tempNodeZ.setLocation(e.x, e.y);
  });
}

// 右键弹出菜单
function handler (event, node) {
  // console.log(node);
  currentNode = node;
  if (event.button === 2) {
    // console.log(event);
    $('#contextmenu').css({
      top: event.layerY,
      left: event.layerX + 40
    }).show();
  }
}  


// 获取节点信息
function getNodes(callback) {
  $.ajax({
    type: "get",
    url: "/control_path_nodes",
    success: function (response) {
      if (response.errmsg === 'success') {
        callback(JSON.parse(response.data));
      }
    }
  });
}

function getTemplates(callback) {
  $.ajax({
    type: 'get',
    url: '/api_templates',
    success: function(response) {
      if (response.err_msg === 'success') {
        callback(response.data);
      }
    }
  })
}

// 应用模板
function applyTemplate(tid) {
  if(currentNode.text === '192.168.0.13') {
    currentNode.text = 'cpe2';
  }
  $.ajax({
    type: 'post',
    url: '/apply_vpn_template',
    contentType: "application/json",
    data: JSON.stringify({
      tid: tid,
      ip: currentNode.ip,
      node_name: currentNode.text
    })
  }).done(function(response){
    if (response.status === 0) {
      alert('应用成功');
      templateTable.ajax.reload();  
    } else {
      alert(response.errmsg)
    }
  })
}

// 跳转至编辑模板页面
function editTemplate(tid) {
  window.location.href = '/template/edit/' + tid;
}

