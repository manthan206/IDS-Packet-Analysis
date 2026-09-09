window.TopologyModule = (() => {
  let simulation = null;

  async function renderGraph() {
    const container = document.getElementById('topology-container');
    container.innerHTML = ''; // Clear existing graph

    const width = container.clientWidth;
    const height = container.clientHeight;

    try {
      const data = await API.getTopology();
      if (!data.nodes || data.nodes.length === 0) {
        container.innerHTML = '<div style="text-align: center; margin-top: 150px; color: var(--text-muted);">No network connections recorded yet to draw topology.</div>';
        return;
      }

      const svg = d3.select('#topology-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

      simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2));

      // Draw links
      const link = svg.append('g')
        .selectAll('line')
        .data(data.links)
        .enter().append('line')
        .attr('stroke', '#00f2fe')
        .attr('stroke-opacity', 0.4)
        .attr('stroke-width', 1.5);

      // Draw nodes
      const node = svg.append('g')
        .selectAll('g')
        .data(data.nodes)
        .enter().append('g')
        .call(d3.drag()
          .on('start', dragstarted)
          .on('drag', dragged)
          .on('end', dragended));

      node.append('circle')
        .attr('r', d => d.group === 1 ? 12 : 8)
        .attr('fill', d => d.group === 1 ? '#00f2fe' : '#f43f5e')
        .attr('stroke', '#fff')
        .attr('stroke-width', 1.5)
        .attr('shadow-glow', '0 0 10px #00f2fe');

      node.append('text')
        .text(d => d.id)
        .attr('x', 15)
        .attr('y', 4)
        .attr('fill', '#94a3b8')
        .attr('font-size', '11px')
        .attr('font-family', 'JetBrains Mono');

      simulation.on('tick', () => {
        link
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y);

        node
          .attr('transform', d => `translate(${d.x},${d.y})`);
      });

      function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
      }

      function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
      }

      function dragended(event) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
      }

    } catch (e) {
      container.innerHTML = `<div style="text-align: center; margin-top: 150px; color: var(--accent-rose);">Failed to render topology: ${e.message}</div>`;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const btnRefresh = document.getElementById('btn-refresh-topology');
    if (btnRefresh) btnRefresh.addEventListener('click', renderGraph);
  });

  return {
    refresh: renderGraph
  };
})();
