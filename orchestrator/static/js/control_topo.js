$(document).ready(function(){
  console.log(JTopo.Effect);
  var canvas = document.getElementById('canvas'); 
  var stage = new JTopo.Stage(canvas); // 创建一个舞台对象

  var scene = new JTopo.Scene(stage); // 创建一个场景对象
  scene.background = '/static/images/bg.jpg';
  
  // 创建公网节点
  var local = createSingleNode({
    x: 500,
    y: 250,
    w: 40,
    h: 40,
    text: 'Cloud-GW',
    img: 'control-cloud.png',
    dragable: false
  }, scene);

  // makeNodeEditable(scene);

  var menuList = $('#contextmenu'),
  menuItem = menuList.find('a');
  
  menuItem.click(function() {
    if($(this)[0].id === 'config-template') {
      $('#config-template-modal').modal();
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
      node.x = Math.random() * 600;
      node.y = Math.random() * 500;
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
  var node = new JTopo.Node(nodeInfo.text);
  node.setLocation(nodeInfo.x, nodeInfo.y);
  node.setSize(nodeInfo.w, nodeInfo.h);
  if (nodeInfo.img) {
    node.setImage('/static/images/' + nodeInfo.img, true);
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

